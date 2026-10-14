from flask import Flask, request, render_template
import paramiko
import socket
import ftplib
import subprocess
import platform
from smb.SMBConnection import SMBConnection
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

app = Flask(__name__)

MAX_WORKERS = 15
SOCKET_TIMEOUT = 4


def port_open(ip, port, timeout=SOCKET_TIMEOUT):
    """Quick TCP connect check so we can distinguish 'unreachable' from 'auth failed'."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def check_ping(ip, username=None, password=None, port=None):
    """ICMP ping using the OS ping binary (works without admin/root privileges)."""
    result = {"ip": ip, "service": "PING", "port": "-", "status": "error", "detail": ""}
    count_flag = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"
    timeout_val = "2000" if platform.system().lower() == "windows" else "2"
    try:
        proc = subprocess.run(
            ["ping", count_flag, "1", timeout_flag, timeout_val, ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=5, text=True
        )
        if proc.returncode == 0:
            result["status"] = "success"
            result["detail"] = "Host is UP (ICMP reply received)"
        else:
            result["status"] = "unreachable"
            result["detail"] = "Host is DOWN or ICMP blocked (no reply)"
    except subprocess.TimeoutExpired:
        result["status"] = "unreachable"
        result["detail"] = "Host is DOWN or ICMP blocked (timeout)"
    except Exception as e:
        result["status"] = "error"
        result["detail"] = str(e)
    return result


def check_smb(ip, username, password, port):
    result = {"ip": ip, "service": "SMB", "port": port, "status": "error", "detail": ""}
    if not port_open(ip, port):
        result["status"] = "unreachable"
        result["detail"] = f"Port {port} closed/filtered or host down"
        return result
    try:
        conn = SMBConnection(username, password, "pentest-client", ip, use_ntlm_v2=True)
        connected = conn.connect(ip, port, timeout=SOCKET_TIMEOUT)
        if connected:
            result["status"] = "success"
            result["detail"] = "Authentication successful"
            conn.close()
        else:
            result["status"] = "failed"
            result["detail"] = "Authentication failed (bad credentials)"
    except Exception as e:
        result["status"] = "error"
        result["detail"] = str(e)
    return result


def check_ssh(ip, username, password, port):
    result = {"ip": ip, "service": "SSH", "port": port, "status": "error", "detail": ""}
    if not port_open(ip, port):
        result["status"] = "unreachable"
        result["detail"] = f"Port {port} closed/filtered or host down"
        return result
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, port=port, username=username, password=password,
                    timeout=SOCKET_TIMEOUT, banner_timeout=SOCKET_TIMEOUT, auth_timeout=SOCKET_TIMEOUT)
        stdin, stdout, stderr = ssh.exec_command("whoami")
        whoami = stdout.read().decode().strip()
        result["status"] = "success"
        result["detail"] = f"Logged in as: {whoami}" if whoami else "Authentication successful"
    except paramiko.AuthenticationException:
        result["status"] = "failed"
        result["detail"] = "Authentication failed (bad credentials)"
    except Exception as e:
        result["status"] = "error"
        result["detail"] = str(e)
    finally:
        ssh.close()
    return result


def check_ftp(ip, username, password, port):
    result = {"ip": ip, "service": "FTP", "port": port, "status": "error", "detail": ""}
    if not port_open(ip, port):
        result["status"] = "unreachable"
        result["detail"] = f"Port {port} closed/filtered or host down"
        return result
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=SOCKET_TIMEOUT)
        ftp.login(username, password)
        result["status"] = "success"
        result["detail"] = "Authentication successful"
        ftp.quit()
    except ftplib.error_perm as e:
        result["status"] = "failed"
        result["detail"] = f"Authentication failed - {e}"
    except Exception as e:
        result["status"] = "error"
        result["detail"] = str(e)
    return result


def run_checks(ip_list, username, password, smb_enabled, ssh_enabled, ftp_enabled, ping_enabled, custom_port):
    jobs = []
    smb_port = custom_port if custom_port else 445
    ssh_port = custom_port if custom_port else 22
    ftp_port = custom_port if custom_port else 21

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for ip in ip_list:
            ip = ip.strip()
            if not ip:
                continue
            if ping_enabled:
                futures.append(executor.submit(check_ping, ip))
            if smb_enabled:
                futures.append(executor.submit(check_smb, ip, username, password, smb_port))
            if ssh_enabled:
                futures.append(executor.submit(check_ssh, ip, username, password, ssh_port))
            if ftp_enabled:
                futures.append(executor.submit(check_ftp, ip, username, password, ftp_port))

        for future in as_completed(futures):
            jobs.append(future.result())

    # Sort: successes first, then failed, then unreachable/error, grouped by IP
    status_order = {"success": 0, "failed": 1, "error": 2, "unreachable": 3}
    jobs.sort(key=lambda r: (r["ip"], status_order.get(r["status"], 4)))
    return jobs


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        start = time.time()
        ip_addresses = request.form.get("ip_addresses", "").splitlines()
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        smb_enabled = bool(request.form.get("smb_enabled"))
        ssh_enabled = bool(request.form.get("ssh_enabled"))
        ftp_enabled = bool(request.form.get("ftp_enabled"))
        ping_enabled = bool(request.form.get("ping_enabled"))
        custom_port_enabled = bool(request.form.get("custom_port_enabled"))
        custom_port_raw = request.form.get("custom_port", "").strip()
        custom_port = int(custom_port_raw) if (custom_port_enabled and custom_port_raw.isdigit()) else None

        results = []
        if smb_enabled or ssh_enabled or ftp_enabled or ping_enabled:
            results = run_checks(ip_addresses, username, password,
                                  smb_enabled, ssh_enabled, ftp_enabled, ping_enabled, custom_port)

        elapsed = round(time.time() - start, 2)
        summary = {
            "total": len(results),
            "success": sum(1 for r in results if r["status"] == "success"),
            "failed": sum(1 for r in results if r["status"] == "failed"),
            "unreachable": sum(1 for r in results if r["status"] == "unreachable"),
            "error": sum(1 for r in results if r["status"] == "error"),
            "elapsed": elapsed,
        }
        return render_template("index.html", results=results, summary=summary, submitted=True)

    return render_template("index.html", results=None, summary=None, submitted=False)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
