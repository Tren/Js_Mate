import os
import re
import sys

# 定义正则表达式列表
patterns = [
    re.compile(r"(['\"]\/[^][^>< \)\(\{\}]*?['\"])"),
    re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'),
    re.compile(r"\d+\.\d+\.\d+\.\d+"),
    re.compile(r'(?:^|_)((?:username|password|key|auv)_)\s*[:=><]*\s*["\']([^"\']+)["\']'),
    re.compile(r'''(['"]\s*(?:GOOG[\w\W]{10,30}|AZ[A-Za-z0-9]{34,40}|AKID[A-Za-z0-9]{13,20}|AKIA[A-Za-z0-9]{16}|IBM[A-Za-z0-9]{10,40}|OCID[A-Za-z0-9]{10,40}|LTAI[A-Za-z0-9]{12,20}|AK[\w\W]{10,62}|AK[A-Za-z0-9]{10,40}|UC[A-Za-z0-9]{10,40}|QY[A-Za-z0-9]{10,40}|KS3[A-Za-z0-9]{10,40}|LTC[A-Za-z0-9]{10,60}|YD[A-Za-z0-9]{10,60}|CTC[A-Za-z0-9]{10,60}|YYT[A-Za-z0-9]{10,60}|YY[A-Za-z0-9]{10,40}|CI[A-Za-z0-9]{10,40}|gcore[A-Za-z0-9]{10,30})\s*['"])'''),
    re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b'),
    re.compile(r'["\'](?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}["\']'),
    re.compile(r'eyJ[A-Za-z0-9_/+\-]{10,}={0,2}\.[A-Za-z0-9_/+\-\\]{15,}={0,2}\.[A-Za-z0-9_/+\-\\]{10,}={0,2}'),
    re.compile(r'-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[a-zA-Z0-9\/\n\r=+]*-----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----'),
    re.compile(r'["\[\s]*[Aa]uthorization["\]\s]*\s*[:=]\s*[\'"]?\b(?:[Tt]oken\s+)?[a-zA-Z0-9\-_+/]{20,500}[\'"]?'),
    re.compile(r'\b[Bb]asic\s+[A-Za-z0-9+/]{18,}={0,2}\b'),
    re.compile(r'\b[Bb]earer\s+[a-zA-Z0-9\-=._+/\\]{20,500}\b'),
    re.compile(r'\b(?:VUE|APP|REACT)_[A-Z_0-9]{1,15}_(?:KEY|PASS|PASSWORD|TOKEN|APIKEY)[\'"]*[:=]"(?:[A-Za-z0-9_\-]{15,50}|[a-z0-9/+]{50,100}==?)"'),
    re.compile(r'\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b'),
    re.compile(r'\bglc_[A-Za-z0-9\-_+/]{32,200}={0,2}\b'),
    re.compile(r'\beyJrIjoi[a-zA-Z0-9\-_+/]{50,100}={0,2}\b'),
    re.compile(r'\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b'),
    re.compile(r'\b(glpat-[a-zA-Z0-9\-=_]{20,22})\b'),
    re.compile(r'\*/(.*)'),
    re.compile(r'//[^\n]*'),
    re.compile(r'/\*(.*)'),
    re.compile(r'<!--(?:.|\n)*?-->'),
]

def find_sensitive_info(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.js'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for pattern in patterns:
                        matches = pattern.findall(content)
                        if matches:
                            print(f'Found in {file_path} using pattern {pattern.pattern}:')
                            for match in matches:
                                print(f'  {match}')

# 从命令行获取要遍历的目录
if len(sys.argv) != 2:
    print("Usage: python find_sensitive_info.py <directory_to_search>")
    sys.exit(1)

directory_to_search = sys.argv[1]
find_sensitive_info(directory_to_search)
