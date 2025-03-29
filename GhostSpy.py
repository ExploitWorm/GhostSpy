import requests
import whois
import nmap
import pyfiglet
import json
import argparse
import ipaddress
from rich.console import Console
from rich.table import Table
from termcolor import colored
from ipwhois import IPWhois
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import sys

# إعدادات المظهر
console = Console()
logo = pyfiglet.figlet_format("GhostSpy", font="slant")
colored_text = colored(logo, color="green")
print(colored_text)

# عرض القائمة الرئيسية
def display_menu():
    print("WELCOME TO GHOSTSPY")
    console.print("[yellow]V2[/yellow]")
    print("EXPLOIT_WORM")
    print("_" * 20)
      
    print("TIKTOK: exploit_worm7")
    print("YOUTUBE: https://www.youtube.com/@Exploit_Worm")
    print("X" * 50)
    
    console.print('1- TRACK IP', style="bold white on red")
    console.print("2- SCAN PORT", style="bold white on red")
    console.print("3- GOBUSTER", style="bold white on red")
    console.print("4- EXIT", style="bold white on red")
    console.print("[red]help --> python3 GhostSpy.py help[/red]")
    print("X" * 50)
    time.sleep(3)

# عرض المساعدة
def show_help():
    print("Usage: python3 GhostSpy.py [command]")
    console.print("[green]Commands:[/green]")
    console.print("[green]  help        Show this help message[/green]")
    console.print("[green]  (No command) Start the main program[/green]")
    

# التحقق من صحة عنوان IP
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# استعلام عن بيانات الـ IP من ipinfo.io
def query_ipinfo(ip):
    url = f"https://ipinfo.io/{ip}/json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        console.print(f"[red]ipinfo Error: {e}[/red]")
        return None

# استعلام عن بيانات الـ IP من ip-api.com
def query_ipapi(ip):
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        console.print(f"[red]ip-api Error: {e}[/red]")
        return None

# دمج البيانات من المصادر المختلفة
def merge_results(ipinfo_data, ipapi_data):
    merged = {}
    if ipinfo_data:
        merged.update(ipinfo_data)
    if ipapi_data and ipapi_data.get("status") == "success":
        merged["countryCode"] = ipapi_data.get("countryCode", merged.get("countryCode", ""))
        merged["regionName"] = ipapi_data.get("regionName", merged.get("region", ""))
        merged["zip"] = ipapi_data.get("zip", merged.get("postal", ""))
        merged["lat"] = str(ipapi_data.get("lat", ""))
        merged["lon"] = str(ipapi_data.get("lon", ""))
        merged["isp"] = ipapi_data.get("isp", "")
        merged["as"] = ipapi_data.get("as", "")
    return merged

# استعلام WHOIS
def query_whois(ip):
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        return result
    except Exception as e:
        console.print(f"[red]Whois Error: {e}[/red]")
        return None

# فحص البورتات باستخدام nmap
def scan_ports(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, '1-1024', arguments='-sS')
        ports = {}
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                ports[proto] = list(nm[ip][proto].keys())
        return ports
    except Exception as e:
        console.print(f"[red]Port scan error: {e}[/red]")
        return None

# معالجة بيانات الـ IP
def process_ip(ip):
    data = {"ip": ip}
    if not is_valid_ip(ip):
        console.print(f"[yellow]العنوان {ip} غير صالح.[/yellow]")
        return {"ip": ip, "error": "IP غير صالح"}

    ipinfo_data = query_ipinfo(ip)
    ipapi_data = query_ipapi(ip)
    merged = merge_results(ipinfo_data, ipapi_data)
    data["merged"] = merged
    data["whois"] = query_whois(ip)
    data["ports"] = scan_ports(ip)

    return data

# عرض النتائج باستخدام rich
def display_results(results):
    for data in results:
        ip = data.get("ip", "غير معروف")
        table = Table(title=f"معلومات IP: {ip}")
        table.add_column("KEY", style="cyan", justify="right")
        table.add_column("VALUE", style="magenta")

        if "error" in data:
            table.add_row("Error", data["error"])
        else:
            merged = data.get("merged", {})
            for key, value in merged.items():
                table.add_row(str(key), str(value))
            if "whois" in data and data["whois"]:
                table.add_row("WHOIS", "متوفر")
            if "ports" in data and data["ports"]:
                table.add_row("Open Ports", str(data["ports"]))

        console.print(table)

# حفظ النتائج في ملف JSON
def save_results(results, output_file):
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=4)
        console.print(f"[green]تم حفظ النتائج في {output_file}[/green]")
    except Exception as e:
        console.print(f"[red]خطأ أثناء حفظ النتائج: {e}[/red]")

# وظيفة GOBUSTER (استكشاف المسارات)
def rae_folder_list(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines() if line.strip()]

def check_folders(base_url, guesses):
    found_folders = []
    for folder in guesses:
        folder_url = f"{base_url}/{folder}"
        time.sleep(2)
        response = requests.get(folder_url)
        if response.status_code == 200:
            found_folders.append(folder_url)
            print(f"200>>>>>>: {folder_url}")
        else:
            print(f"401 Error: {folder_url}")
    return found_folders

# الوظيفة الرئيسية
def main():
    display_menu()
    Enter = input("> ")

    if Enter == "1":
        ip = input("Enter IP: ")
        result = process_ip(ip)
        display_results([result])
    elif Enter == "2":
        ip = input("Enter IP: ")
        ports = scan_ports(ip)
        if ports:
            console.print(f"[green]البورتات المفتوحة: {ports}[/green]")
        else:
            console.print("[red]لم يتم العثور على بورتات مفتوحة أو خطأ في الفحص[/red]")
    elif Enter == "3":
        url = input("ENTER URL : ")
        list_file = input("ENTER WORDLIST : ")

        folder_list = rae_folder_list(list_file)
        found_folder = check_folders(url, folder_list)

        if found_folder:
            print("\n ok folder : ")
            for folder in found_folder:
                print(folder)
        else:
            print("\nError")
    elif Enter == "4":
        console.print("[red]Good bye[/red]")
        exit()
    else:
        console.print("[red]ERROR OPTION[/red]")

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == "help":
        show_help()
    else:
        main()