# Written by Sangameswaran R S #

import re
from urllib.request import urlopen

from bs4 import BeautifulSoup
from tld import get_tld

from train import train_and_export_model


def entry_point():
    print('[INFO] Initializing Script')
    clf = train_and_export_model()
    while True:
        site_url = input("Enter website to be checked..")
        site_info = site_processing(site_url)
        if site_info:
            result = clf.predict([site_info])
            print(result)
            if result[0] == '1':
                print(" [+] PHISHED")
            elif result == '0':
                print(" [.] SUSPICIOUS")
            else:
                print(" [-] NOT PHISHED")
        else:
            print('[INFO] Unable to predict')
        choice = input('Try another webpage? [y/n] :')
        if choice == 'y':
            continue
        else:
            break
    print('[INFO] Prediction Complete ')


def site_processing(site_url):
    print('[INFO] Processing ' + str(site_url))
    try:
        site = urlopen(site_url)
        soup = BeautifulSoup(str(site.read()), 'html.parser')
    except Exception as s:
        print('-----------[FATAL]-------------')
        print(s)
        print('--------------------------------')
        return None
    try:
        ip_err_flag = False
        domain_info = get_tld(site_url, as_object=True)
        complete_url = site_url
        domain_only = str(domain_info.subdomain) + '.' + str(domain_info.fld)
        global_domain_only = domain_info.fld
        domain_only_without_www = domain_only.replace("www.", "")
    except Exception as E:
        print('[EXCEPTION] :' + str(E))
        ip_err_flag = True
        complete_url = site_url
        domain_only = site_url
        global_domain_only = ''
        domain_only_without_www = site_url
    ip_regex = "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
    ip_hex_regex = "0x[0-9][A-F]\.0x[0-9][A-F]\.0x[0-9][A-F]\.0x[0-9][A-F]"
    # Condition 1: Ip in URL
    re_match_ip = re.match(ip_regex, domain_only_without_www)
    re_match_hex_ip = re.match(ip_hex_regex, domain_only_without_www)
    if re_match_hex_ip or re_match_ip:
        c1 = 1
    else:
        c1 = -1
    print('[DEBUG] Condition 1 -IP Feature: ' + str(c1))
    # Condition 2 URL Length
    if complete_url.__len__() < 54:
        c2 = -1
    elif 54 < complete_url.__len__() < 75:
        c2 = 0
    else:
        c2 = 1
    print('[DEBUG] Condition 2 - URL Length: ' + str(c2))
    # Condition 3 Tiny URL
    if domain_only.__len__() < 10:
        c3 = 1
    else:
        c3 = -1
    print('[DEBUG] Condition 3 - Tiny URL: ' + str(c3))
    # Condition 4 Presence of @ Symbol
    if "@" in complete_url:
        c4 = 1
    else:
        c4 = -1
    print('[DEBUG] Condition 4 - @ Presence: ' + str(c4))
    # Condition 5 Last Index of //
    if complete_url.rfind("//") > 7:
        c5 = 1
    else:
        c5 = -1
    print('[DEBUG] Condition 5 Last Index of //: ' + str(c5))
    # Condition 6 - in URL Domain
    if "-" in domain_only_without_www:
        c6 = 1
    else:
        c6 = -1
    print('[DEBUG] Condition 6 - Presence: ' + str(c6))
    # Condition 7 Number of Sub domains
    if ip_err_flag:
        c7 = -1
    else:
        if domain_only.count(".") >= 4:
            c7 = 1
        elif 1 <= domain_only.count(".") <= 2:
            c7 = -1
        else:
            c7 = 0
    print("[DEBUG] Condition 7 Sub domain Count: " + str(c7))
    # Condition 8 Using HTTPS
    try:
        if complete_url.index('s') == 4:
            c8 = -1
        else:
            c8 = 1
    except Exception:
        c8 = 1
    print('[DEBUG] Condition 8 HTTPS Test: ' + str(c8))
    # Condition 9 Domain Registration Length:
    c9 = -1
    print('[DEBUG] Condition 9 Domain Registration Length: ' + str(c9))
    # Condition 10 Favicon domain Check
    c10 = -1
    print('[DEBUG] Condition 10 Favicon check: ' + str(c10))
    # Condition 11 Using non-standard port:
    if ":80/" in complete_url or ":443/" in complete_url:
        c11 = -1
    else:
        port_regex_matcher = re.search(":[0-9]+/", complete_url)
        if port_regex_matcher:
            c11 = 1
        else:
            c11 = -1
    print('[DEBUG] Condition 11 Non standard port: ' + str(c11))
    # Condition 12 Https in URL Domain part
    if "https" in domain_only_without_www:
        c12 = 1
    else:
        c12 = -1
    print('[DEBUG] Condition 12 protocol check in domain only part: ' + str(c12))
    # Condition 13 Request URL:
    legit_links = 0
    suspicious_links = 0
    print('[DEBUG] Checking img tag links')
    for link in soup.findAll("img"):
        link_src = link.get('src')
        print("         [URL]" + str(link_src))
        try:
            current_domain_info = get_tld(link_src, as_object=True)
            current_fld = current_domain_info.fld
            if global_domain_only == current_fld:
                legit_links = legit_links + 1
            else:
                suspicious_links = suspicious_links + 1
        except Exception as e1:
            print('[EXCEPTION] ' + str(e1))
            legit_links = legit_links + 1
    print(legit_links, suspicious_links)
    total_links = legit_links + suspicious_links
    if total_links == 0:
        suspected_percentage = 0
    else:
        suspected_percentage = (suspicious_links / total_links) * 100
    if suspected_percentage < 22:
        c13 = -1
    elif 22 <= suspected_percentage <= 61:
        c13 = 0
    else:
        c13 = 1
    print('[DEBUG] Condition 13 Request URL Same Domain Check: ' + str(c13))
    # Condition 14: Request URL in anchor tag
    legit_a_links = 0
    suspicious_a_links = 0
    print('[DEBUG] Checking all anchor tag links')
    for link in soup.findAll("a"):
        link_src = link.get("href")
        print("         [URL]" + str(link_src))
        try:
            current_domain_info = get_tld(link_src, as_object=True)
            current_domain = str(current_domain_info.subdomain) + "." + str(current_domain_info.fld)
            current_fld = current_domain_info.fld
            print("[DEBUG] -- " + str(current_domain) + "," + str(domain_only))
            if current_fld == global_domain_only:
                legit_a_links = legit_a_links + 1
            else:
                suspicious_a_links = suspicious_a_links + 1
        except Exception:
            legit_a_links = legit_a_links + 1
    print(legit_a_links, suspicious_a_links)
    total_a_links = legit_a_links + suspicious_a_links
    if total_a_links == 0:
        suspected_percentage = 0
    else:
        suspected_percentage = (suspicious_a_links / total_a_links) * 100
    if suspected_percentage < 31:
        c14 = -1
    elif 31 < suspected_percentage < 67:
        c14 = 0
    else:
        c14 = 1
    print('[DEBUG] Condition 14 Anchor Tag Request URL: ' + str(c14))
    # Condition 23 Having iframe
    iframe_count = 0
    for _ in soup.findAll("iframe"):
        iframe_count = iframe_count + 1
    if iframe_count > 0:
        c23 = 1
    else:
        c23 = -1
    print('[DEBUG] Condition 23 Iframe Presence: ' + str(c23))
    input_list = [c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c23]
    return input_list


entry_point()
