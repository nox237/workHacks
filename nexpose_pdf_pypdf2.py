#!/usr/bin/python3

import re
import sys
import getopt
import PyPDF2
from termcolor import colored
from prettytable import PrettyTable

if sys.platform == "linux" or sys.platform == "linux2":
    # linux
    pass
elif sys.platform == "darwin":
    # MAC OS X
    pass
elif sys.platform == "win32" or sys.platform == "win64":
    # Windows 32-bit or Windows 64-bit
    import colorama
    colorama.init()

def get_vulnerability_data(list_heading):
    list_vulnerability = []
    for idx,heading in enumerate(list_heading):
        vulnerability_object = {}
        vulnerability_object['title'] = heading
        pattern_string = ""
        if idx == len(heading_vulnerability) - 1:
            pattern_string = re.escape(heading) + "(.*?)" + r"4. Remediation Plan"
        else:
            pattern_string = re.escape(heading) + "(.*?)" + re.escape(heading_vulnerability[idx+1])
        pattern = re.compile(pattern_string)
        text_vulnerability = re.findall(pattern, all_text)[0]
            
        severity = ""
        unknown_severity = re.findall("Severity(\w+)", text_vulnerability)[0]
        for idx, status in enumerate(["Critical", "High", "Medium", "Low"]):
            if status in unknown_severity:
                severity = status
                break
            elif idx == 4:
                severity = "Unknown"
        vulnerability_object['severity'] = severity

        cvss_v2 = re.findall(r"CVSSv2 Score(\d\.\d)", text_vulnerability)[0] if len(re.findall(r"CVSSv2 Score(\d\.\d)", text_vulnerability)) else "0.0"
        cvss_v3 = re.findall(r"CVSSv3 Score(\d\.\d)", text_vulnerability)[0] if len(re.findall(r"CVSSv3 Score(\d\.\d)", text_vulnerability)) else "0.0"
        vulnerability_object['cvss_v2'] = float(cvss_v2)
        vulnerability_object['cvss_v3'] = float(cvss_v3)

        vulnerability_ip_list = []
        for ip in ip_list:
            if ip in text_vulnerability:
                vulnerability_ip_list.append(ip)
        vulnerability_object['ip'] = vulnerability_ip_list

        vulnerability_object['problem'] = {}
        for ip in vulnerability_object['ip']:
            vulnerability_object['problem'][ip] = list(re.findall(ip + r"(\d{1,5}\/tcp|udp)", text_vulnerability))

        solution = re.findall(r"Solution(.+)", text_vulnerability)
        vulnerability_object['solution'] = solution[0].strip()

        if re.match(r".*Page \d+CONFIDENTIAL", solution[0]):
            solution = re.findall(r"(.*)Page \d+CONFIDENTIAL", solution[0])[0].strip()
        else:
            solution = solution[0].strip()
        list_vulnerability.append(vulnerability_object)
    return list_vulnerability

def help():
    print('-o / --output        : output file')
    print('-a / --ip-address    : ip address file')
    print('-i / --pdf           : input pdf file')
    print('-h / --help          : help function')

if __name__ == "__main__":

    pdf_path = ""
    ip_path = ""
    output_path = ""
    ip_list = []

    opts, args = getopt.getopt(sys.argv[1:], "o:a:i:h", ["output=", "pdf=", "ip-address=", "help"])

    for opt, val in opts:
        if opt in ("-o","--output"):
            output_path = val
        elif opt in ("-a", "--ip-address"):
            ip_path = val
        elif opt in ("-i", "--pdf"):
            pdf_path = val
        elif opt in ("-h", "--help"):
            help()
            exit(0)

    if ip_path != "":
        with open(ip_path) as f:
            ip_list = f.read().split()

    if pdf_path == "":
        print('[!] There is no pdf')
        exit(0)

    pdfFileObject = open(pdf_path, 'rb')
    pdfReader = PyPDF2.PdfFileReader(pdfFileObject)
    all_text = ""

    print("[!] Getting all the text inside the pdf")
    for i in range(0,pdfReader.numPages):
        pageObj = pdfReader.getPage(i)
        all_text += pageObj.extractText()
    pdfFileObject.close()

    print("[!] Processing the text from the pdf")
    list_heading = []
    heading_vulnerability = re.findall(r"(\d\.\d\.\d+\. [\w\ \:\-\(\)\.\/]+)Severity", all_text)
    for heading in heading_vulnerability:
        if re.match(r".*Page \d+CONFIDENTIAL", heading):
            heading_sanitize = re.findall(r"(.*)Page \d+CONFIDENTIAL", heading)[0]
        else:
            heading_sanitize = heading
        list_heading.append(heading_sanitize)

    print("[!] Getting all vulnerability data via regex")
    list_vulnerability = get_vulnerability_data(list_heading)
    
    x = PrettyTable()
    x.field_names = ['Vulnerability Name', 'IP', 'Port', 'Severity', 'CVSS v3', 'CVSS v2']
    x.align['Vulnerability Name'] = "l"

    print('[!] Printing all vulnerability')

    total_len = 0
    for vulnerability in list_vulnerability:
        x.add_row([vulnerability['title'], '', '', vulnerability['severity'], vulnerability['cvss_v3'], vulnerability['cvss_v2']])
        total_len += 1
        for ip in vulnerability['problem']:
            for port in vulnerability['problem'][ip]:
                x.add_row(['', ip, port, '', '', ''])
                total_len += 1
            
        
    print(x)
    print()

    x = PrettyTable()
    x.field_names = ['Vulnerability Name', 'Severity', 'CVSS v3', 'CVSS v2']
    x.align['Vulnerability Name'] = "l"
    print('[!] Printing all vulnerability where cvss_v2 and cvss_v3 score is higher than 5.0')
    for vulnerability in list_vulnerability:
        if vulnerability['cvss_v3'] >= 5.0 or vulnerability['cvss_v2'] >= 5.0:
            x.add_row([vulnerability['title'], vulnerability['severity'], vulnerability['cvss_v3'], vulnerability['cvss_v2']])
    print(x)
    print()

    print('[!] Printing total vulnerability based on the ip tables')
    if ip_list != []:
        # initialize dictionary_list
        dictionary_list = {"Critical":{}, "High":{}, "Medium":{}, "Low":{}}
        for ip in ip_list:
            dictionary_list["Critical"][ip] = 0
            dictionary_list["High"][ip] = 0
            dictionary_list["Medium"][ip] = 0
            dictionary_list["Low"][ip] = 0

        for vulnerability in list_vulnerability:
            for ip in ip_list:
                if vulnerability['severity'] == "Critical" and ip in vulnerability['ip']:
                    dictionary_list['Critical'][ip] += 1
                if vulnerability['severity'] == "High" and ip in vulnerability['ip']:
                    dictionary_list['High'][ip] += 1
                elif vulnerability['severity'] == "Medium" and ip in vulnerability['ip']:
                    dictionary_list['Medium'][ip] += 1
                elif vulnerability['severity'] == "Low" and ip in vulnerability['ip']:
                    dictionary_list["Low"][ip] += 1

        x = PrettyTable()
        x.field_names = ['IP Address', 'Critical', 'High', 'Medium', "Low"]
        for ip in ip_list:
            x.add_row([ip, dictionary_list['Critical'][ip], dictionary_list['High'][ip], dictionary_list['Medium'][ip], dictionary_list['Low'][ip]])
        print(x)
    else:
        print('[!] There is no ip supplied')
    
    if output_path != '':
        import docx
        import datetime
        ress = re.findall(r'(\d{8})\_(\w+)', pdf_path)[0]
        filename = ress[1]
        date = ress[0]
        print(date, filename)

        save_doc = docx.Document()
        table = save_doc.add_table(rows=1, cols=6)
        row = table.rows[0].cells
        row[0].text = 'Vulnerability Name'
        row[1].text = 'IP'
        row[2].text = 'Port'
        row[3].text = 'Severity'
        row[4].text = 'CVSS v3'
        row[5].text = 'CVSS v2'

        for vuln in list_vulnerability:
            row = table.add_row().cells
            row[0].text = vuln['title']
            row[1].text = ''
            row[2].text = ''
            row[3].text = vuln['severity']
            row[4].text = str(vuln['cvss_v3'])
            row[5].text = str(vuln['cvss_v2'])
            for ip in vuln['problem']:
                for port in vuln['problem'][ip]:
                    row = table.add_row().cells
                    row[0].text = ''
                    row[1].text = ip
                    row[2].text = port
                    row[3].text = ''
                    row[4].text = ''
                    row[5].text = ''
        
        save_doc.save(output_path + '/' + date + '_' + filename + '.docx')