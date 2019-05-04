#!/usr/bin/python
import sys
import re
import json
import json
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi
#fromFieldAndReplyToMatch = False
#pathElementsMatch = False

def mergeWarnings(warnings, warningsToAdd):
	for warning in warningsToAdd:
		warnings.append(warning)
	return warnings

def removeText(textToRemove, text):
	text = text.replace(textToRemove, "")
	return text

def readWholeMail():
	email = sys.stdin.readlines()
	email = "".join(email)
	return email

def getFromField(email):
	fromField = re.findall("[Ff]rom: .*\n?", email)
	if len(fromField) > 0:
		fromField = removeText("From: ", fromField[0])
		fromField = removeText("from: ", fromField)
		fromField = removeText("From:", fromField)
		fromField = removeText("from:", fromField)
		return fromField
	else:
		return None	

def getReplyToField(email):
	replyToField = re.findall("[Rr]eply-to: .*\n?", email)
	if len(replyToField) > 0:
		replyToField = removeText("Reply-to: ", replyToField[0])
		replyToField = removeText("reply-to: ", replyToField)
		replyToField = removeText("Reply-to:", replyToField)
		replyToField = removeText("reply-to:", replyToField)
		return replyToField
	else:
		return None

def getMail(field):
	mail = re.findall("[a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,5}", field)
	if len(mail) != 1:
		return None
	else:
		return mail[0]

def checkFromAndReply(fromField, replyToField):
	warnings = []
	if fromField != replyToField:
		warnings.append("Warning: From field doesn't mach reply to field!")
	fromMail = getMail(fromField)
	if not fromMail:
		warnings.append("Warning: From field is incorrect!")
	replyMail = getMail(replyToField)
	if not replyMail:	
		warnings.append("Warning: Reply-to field is incorrect!")
	if fromMail != replyMail:
		warnings.append("Warning: Sender mail is different than mail in reply-to field!")
	return warnings

def getReceivedList(email):
	received = []
	ptrn = re.compile("^(Received: from.*?;)", re.MULTILINE|re.DOTALL)
	for match in ptrn.finditer(email):
		match = match.groups()
		received.append(match[0])
	return received

def getFromAndByServerData(receivedRecord):
	fromPtrn = re.compile("from ([a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,5}) \(([a-zA-Z0-9_\-\.]+) \[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]")
	for match in fromPtrn.finditer(receivedRecord):
		fromDomain, resolvedDomain, IP = match.groups()
	return (fromDomain, resolvedDomain, IP)

def checkIfPathIsCorrect(fromList):
	warnings = []
	for fromServer, resolvedDomain, IP in fromList:
		if resolvedDomain != fromServer:
			warnings.append(" ".join(["Warning: in mail path IP", IP, "is resolved as", resolvedDomain, "not", fromServer]))
	return warnings

def matchPath(receivedList):
	fromFields = []
	for item in receivedList:
		fromServer = getFromAndByServerData(item)
		fromFields.append(fromServer)
	warnings = checkIfPathIsCorrect(fromFields)
	return warnings, fromFields[0][0]

def checkPath(email):
	warnings = []
	receivedList = getReceivedList(email)
	if len(receivedList) == 0:
		warnings.append("Warning: couldn't find mail path!")
		return warnings
	receivedList.reverse()
	tmpWarnings, fromDomain = matchPath(receivedList)
	warnings = mergeWarnings(warnings, tmpWarnings)
	return warnings, fromDomain

def getMailId(email):
	mailId = ""
	ptrn = re.compile("Message-I[Dd]: <([a-zA-Z0-9\.\-@]+)>")
	for match in ptrn.finditer(email):
		mailId = match.groups()[0]
	return mailId

def checkSPF(email):
	warnings = []
	ptrn = re.compile("Received-SPF: (\w+)")
	countSPF = 0
	for match in ptrn.finditer(email):
		countSPF = countSPF + 1
		mached - match.groups()[0]
		if mached != "pass":
			warnings.append("".join(["Warning: there is SPF record with ", mached, " status!"]))
	if countSPF == 0:
		warnings.append("Warning: there is no SPF records")
	return warnings

def checkInVirusTotal(fromDomain):
	try:
		API_KEY = '6953d846c57e206154533f8f72136c973877704492c927da6a434a0d13aadd63'
		vt = VirusTotalPublicApi(API_KEY)
		report = vt.get_url_report(fromDomain)
		return ["".join(["VirusTotal report: found ", str(report["results"]["positives"]), " issues in ", str(report["results"]["total"]), " entries"])]
	except:
		return ["Warning: could not retrive VirusTotal report"]

def checkURLs(email):
	warnings = []
	ptrn = re.compile("src=['\"](.*?)['\"]")
	API_KEY = '6953d846c57e206154533f8f72136c973877704492c927da6a434a0d13aadd63'
	vt = VirusTotalPublicApi(API_KEY)
	for match in ptrn.finditer(email):
		try:
			matched = match.groups()[0]
			report = vt.get_url_report(matched)
			warnings.append("".join(["VirusTotal report for: ",
						 matched,
						 " issues: ",
						 str(report["results"]["positives"]),
						 " from ",
						 str(report["results"]["total"])])
						 )
		except:
			warnings.append("".join(["Warning: no VirusTotal report for ", matched]))
	return warnings

warnings = []
email = readWholeMail()

fromField = getFromField(email)
if not fromField or fromField == "": 
	warnings.append("Warning: From field is empty!")
 
replyToField = getReplyToField(email)
if not replyToField or replyToField == "": 
	warnings.append("Warning: replyTo field is empty!")

if fromField and replyToField:
	tmpWarnings = checkFromAndReply(fromField, replyToField)
	warnings = mergeWarnings(warnings, tmpWarnings)

tmpWarnings, fromDomain = checkPath(email)
warnings = mergeWarnings(warnings, tmpWarnings)
tmpWarnings = checkSPF(email)
warnings = mergeWarnings(warnings, tmpWarnings)
tmpWarnings = checkInVirusTotal(fromDomain)
warnings = mergeWarnings(warnings, tmpWarnings)
tmpWarnings = checkURLs(email)
warnings = mergeWarnings(warnings, tmpWarnings)
mailId = getMailId(email)
newMail = "\n".join([email, "\n".join(warnings)])
receipent = sys.argv[3]
atIdx = receipent.find("@")
receipent = receipent[:atIdx]
f = open("/home/"+receipent+"/Maildir/new/"+mailId, "w+")
f.write(newMail)
