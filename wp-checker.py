import requests
import argparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, init

init(autoreset=True)
requests.urllib3.disable_warnings()


def normalize_url(url):
    """Pastikan URL mengarah ke wp-login.php"""
    if not url.startswith("http"):
        url = "http://" + url

    if "wp-login.php" in url:
        return url

    return url.rstrip("/") + "/wp-login.php"


def wp_login(url, username, password):
    """Test login WordPress di localhost / server pribadi dan cek akses admin ke /wp-admin/users.php."""
    login_url = normalize_url(url)
    session = requests.Session()

    try:
        payload = {
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": login_url.replace("wp-login.php", "wp-admin/"),
            "testcookie": "1"
        }

        # GET cookies
        session.get(login_url, timeout=10, verify=False)

        # POST login
        resp = session.post(login_url, data=payload, timeout=15, allow_redirects=True)

        if "wp-admin" in resp.url.lower():
            # Cek akses ke /wp-admin/users.php untuk verifikasi admin
            users_url = login_url.replace("wp-login.php", "wp-admin/users.php")
            resp2 = session.get(users_url, timeout=10, verify=False, allow_redirects=True)
            
            # Verifikasi admin: status 200, tidak redirect ke login, dan tidak ada pesan error permission
            if (resp2.status_code == 200 and 
                "wp-login" not in resp2.url.lower() and 
                "You need a higher level of permission" not in resp2.text and 
                "Sorry, you are not allowed to list users" not in resp2.text):
                print(Fore.GREEN + f"[SUCCESS ADMIN LOGIN] {url} | {username} | {password}")
                return True
            else:
                print(Fore.YELLOW + f"[LOGIN SUCCESS BUT NOT ADMIN] {url} | {username} | {password}")
                return False

        print(Fore.RED + f"[FAILED LOGIN] {url}")
        return False

    except Exception as e:
        print(Fore.RED + f"[ERROR] {url} --> {e}")
        return False


def parse_input_file(filepath):
    """Parse semua format input secara aman."""
    targets = []

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # FORMAT 1: url|user|pass
            if "|" in line:
                parts = line.split("|")
                if len(parts) == 3:
                    url, usr, pwd = parts
                    targets.append((url, usr, pwd))
                else:
                    print(Fore.YELLOW + f"[WARNING] Format salah: {line}")
                continue

            # FORMAT 2: url:user:pass
            if ":" in line:
                try:
                    # Split dari belakang → aman untuk https://
                    url, usr, pwd = line.rsplit(":", 2)
                    targets.append((url, usr, pwd))
                except:
                    print(Fore.YELLOW + f"[WARNING] Format salah: {line}")
                continue

            print(Fore.YELLOW + f"[WARNING] Format tidak valid: {line}")

    return targets


def main():
    parser = argparse.ArgumentParser(description="WordPress Login Checker (Localhost Only) - Admin Verification")
    parser.add_argument("--file", required=True, help="List input")
    parser.add_argument("--threads", type=int, default=5)
    parser.add_argument("-o", default="WP_BERHASIL.txt", help="Output file")

    args = parser.parse_args()

    # LOAD LIST
    targets = parse_input_file(args.file)

    if not targets:
        print(Fore.RED + "Tidak ada target valid dalam file.")
        return

    # MULTITHREAD
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for url, username, password in targets:
            result = executor.submit(wp_login, url, username, password)

            if result.result():
                with open(args.o, "a", encoding="utf-8") as f:
                    f.write(f"{url}|{username}|{password}\n")


if __name__ == "__main__":
    main()
