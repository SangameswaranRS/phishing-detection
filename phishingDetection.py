# Created by Sangameswaran R S #

import arff
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from urllib.request import urlopen
from tld import get_tld
import re
from bs4 import BeautifulSoup


def train_and_export_model():
    print('[INFO] Loading Dataset ')
    dataset = arff.load(open('trainingDatasetUCL.arff', 'r'))
    data = np.array(dataset['data'])
    print('[INFO] Load Complete')
    data = data[:, [0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 22, 30]]
    for feature in dataset['attributes']:
        print('      [.]' + str(feature[0]))
    X, Y = data[:, :-1], data[:, -1]
    print('[INFO] Splitting into training and testing datasets')
    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.3)
    print('[INFO] Training Classifier')
    clf = RandomForestClassifier(n_estimators=20)
    clf.fit(X_train, Y_train)
    accuracy = clf.score(X_test, Y_test)
    print('[INFO] Training Done')
    print("[INFO] Training Accuracy: " + str(accuracy))
    return clf


def entry_point():
    print('[INFO] Initializing Script')
    clf = train_and_export_model()
    while True:
        # result = clf.predict(np.array([[1,1,1,1,1,-1,0,1,-1,-1,1,1,1,0]]))
        siteURL = input("Enter website to be checked..")
        siteInfo = site_processing(siteURL)
        if siteInfo:
            result = clf.predict([siteInfo])
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


def site_processing(siteURL):
    print('[INFO] Processing ' + str(siteURL))
    try:
        site = urlopen(siteURL)
        soup = BeautifulSoup(str(site.read()), 'html.parser')
    except Exception as s:
        print('-----------[FATAL]-------------')
        print(s)
        print('--------------------------------')
        return None
    try:
        ipErrFlag = False
        domainInfo = get_tld(siteURL, as_object=True)
        completeURL = siteURL
        domainOnly = str(domainInfo.subdomain) + '.' + str(domainInfo.fld)
        globalDomainOnly = domainInfo.fld
        domainOnlyWithoutWWW = domainOnly.replace("www.", "")
    except Exception as E:
        print('[EXCEPTION] :' + str(E))
        ipErrFlag = True
        completeURL = siteURL
        domainOnly = siteURL
        globalDomainOnly = ''
        domainOnlyWithoutWWW = siteURL
    ipRegex = "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
    ipHexRegex = "0x[0-9][A-F]\.0x[0-9][A-F]\.0x[0-9][A-F]\.0x[0-9][A-F]"
    # Condition 1: Ip in URL
    reMatchIp = re.match(ipRegex, domainOnlyWithoutWWW)
    reMatchHexIp = re.match(ipHexRegex, domainOnlyWithoutWWW)
    if reMatchHexIp or reMatchIp:
        C1 = 1
    else:
        C1 = -1
    print('[DEBUG] Condition 1 -IP Feature: ' + str(C1))
    # Condition 2 URL Length
    if completeURL.__len__() < 54:
        C2 = -1
    elif 54 < completeURL.__len__() < 75:
        C2 = 0
    else:
        C2 = 1
    print('[DEBUG] Condition 2 - URL Length: ' + str(C2))
    # Condition 3 Tiny URL
    if domainOnly.__len__() < 10:
        C3 = 1
    else:
        C3 = -1
    print('[DEBUG] Condition 3 - Tiny URL: ' + str(C3))
    # Condition 4 Presence of @ Symbol
    if "@" in completeURL:
        C4 = 1
    else:
        C4 = -1
    print('[DEBUG] Condition 4 - @ Presence: ' + str(C4))
    # Condition 5 Last Index of //
    if completeURL.rfind("//") > 7:
        C5 = 1
    else:
        C5 = -1
    print('[DEBUG] Condition 5 Last Index of //: ' + str(C5))
    # Condition 6 - in URL Domain
    if "-" in domainOnlyWithoutWWW:
        C6 = 1
    else:
        C6 = -1
    print('[DEBUG] Condition 6 - Presence: ' + str(C6))
    # Condition 7 Number of Sub domains
    if ipErrFlag:
        C7 = -1
    else:
        if domainOnly.count(".") >= 4:
            C7 = 1
        elif 1 <= domainOnly.count(".") <= 2:
            C7 = -1
        else:
            C7 = 0
    print("[DEBUG] Condition 7 Sub domain Count: " + str(C7))
    # Condition 8 Using HTTPS
    try:
        if completeURL.index('s') == 4:
            C8 = -1
        else:
            C8 = 1
    except Exception:
        C8 = 1
    print('[DEBUG] Condition 8 HTTPS Test: ' + str(C8))
    # Condition 9 Domain Registration Length:
    C9 = -1
    print('[DEBUG] Condition 9 Domain Registration Length: ' + str(C9))
    # Condition 10 Favicon domain Check
    C10 = -1
    print('[DEBUG] Condition 10 Favicon check: ' + str(C10))
    # Condition 11 Using non standard port:
    if ":80/" in completeURL or ":443/" in completeURL:
        C11 = -1
    else:
        portRegexMatcher = re.search(":[0-9]+/", completeURL)
        if portRegexMatcher:
            C11 = 1
        else:
            C11 = -1
    print('[DEBUG] Condition 11 Non standard port: ' + str(C11))
    # Condition 12 Https in URL Domain part
    if "https" in domainOnlyWithoutWWW:
        C12 = 1
    else:
        C12 = -1
    print('[DEBUG] Condition 12 protocol check in domain only part: ' + str(C12))
    # Condition 13 Request URL:
    legitLinks = 0
    suspiciousLinks = 0
    print('[DEBUG] Checking img tag links')
    for link in soup.findAll("img"):
        link_src = link.get('src')
        print("         [URL]" + str(link_src))
        try:
            currentDomainInfo = get_tld(link_src, as_object=True)
            currentFld = currentDomainInfo.fld
            if globalDomainOnly == currentFld:
                legitLinks = legitLinks + 1
            else:
                suspiciousLinks = suspiciousLinks + 1
        except Exception as e1:
            print('[EXCEPTION] ' + str(e1))
            legitLinks = legitLinks + 1
    print(legitLinks, suspiciousLinks)
    totallinks = legitLinks + suspiciousLinks
    if totallinks == 0:
        suspPercentage = 0
    else:
        suspPercentage = (suspiciousLinks / totallinks) * 100
    if suspPercentage < 22:
        C13 = -1
    elif 22 <= suspPercentage <= 61:
        C13 = 0
    else:
        C13 = 1
    print('[DEBUG] Condition 13 Request URL Same Domain Check: ' + str(C13))
    # Condition 14: Request URL in anchor tag
    legitALinks = 0
    suspiciousALinks = 0
    print('[DEBUG] Checking all anchor tag links')
    for link in soup.findAll("a"):
        link_src = link.get("href")
        print("         [URL]" + str(link_src))
        try:
            currentDomainInfo = get_tld(link_src, as_object=True)
            currentDomain = str(currentDomainInfo.subdomain) + "." + str(currentDomainInfo.fld)
            currentFld = currentDomainInfo.fld
            print("[DEBUG] -- " + str(currentDomain) + "," + str(domainOnly))
            if currentFld == globalDomainOnly:
                legitALinks = legitALinks + 1
            else:
                suspiciousALinks = suspiciousALinks + 1
        except Exception:
            legitALinks = legitALinks + 1
    print(legitALinks, suspiciousALinks)
    totalALinks = legitALinks + suspiciousALinks
    if totalALinks == 0:
        suspPercentage = 0
    else:
        suspPercentage = (suspiciousALinks / totalALinks) * 100
    if suspPercentage < 31:
        C14 = -1
    elif 31 < suspPercentage < 67:
        C14 = 0
    else:
        C14 = 1
    print('[DEBUG] Condition 14 Anchor Tag Request URL: ' + str(C14))
    # Condition 23 Having iframe
    iframeCount = 0
    for frame in soup.findAll("iframe"):
        iframeCount =iframeCount + 1
    if iframeCount > 0:
        C23 = 1
    else:
        C23 = -1
    print('[DEBUG] Condition 23 Iframe Presence: '+ str(C23))
    inputList = [C1, C2, C3, C4, C5, C6, C7, C8, C9, C10, C11, C12, C13, C14, C23]
    return inputList


entry_point()
