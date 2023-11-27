#!/usr/bin/env python
# coding: utf-8

# In[3]:


import pandas as pd
import csv

urldata=pd.read_csv('Desktop/data.csv')
urldata.head()


# In[4]:


pip install xgboost


# In[5]:


import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


# In[6]:


X = urldata[['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
                 'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 'Domain_Age', 'Domain_End', 'whois', 'iFrame',
                 'Mouse_Over', 'Right_Click', 'Web_Forwards']]


# In[7]:


y = urldata['Label']


# In[8]:


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = xgb.XGBClassifier(
    learning_rate=0.05,
    n_estimators=300,
    max_depth=5,
    objective='binary:logistic'
)


# In[9]:


model.fit(X_train, y_train)
y_pred = model.predict(X_test)


# In[10]:


accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)


# In[11]:


print(f"Accuracy: {accuracy}")
print(f"Precision: {precision}")
print(f"Recall: {recall}")
print(f"F1-score: {f1}")


# In[12]:


pip install python-whois


# In[13]:


import whois
import pandas as pd


# In[14]:


def extract_whois_data(url):
    try:
        whois_data = whois.whois(url)
        return whois_data
    except Exception as e:
        print(f"Error extracting WHOIS data for {url}: {str(e)}")
        return None


# In[15]:


def calculate_phishing_probability(whois_data):
    if whois_data is None:
        return None

    if 'creation_date' in whois_data:
        creation_date = whois_data['creation_date']
        if isinstance(creation_date, list) and len(creation_date) > 0:

            today = pd.Timestamp.today()
            if (today - creation_date[0]).days <= 365:
                return 1
    return 0


# In[16]:


from urllib.parse import urlparse,urlencode
import ipaddress
import re


# In[17]:


def getDomain(url):
  parsed_url = urlparse(url)

    # Extract the netloc (domain) from the parsed URL
  domain_name = parsed_url.netloc

    # Return the domain name
  return domain_name


# In[26]:


# 2.Checks for IP address in URL (Have_IP)
def havingIP(url):
  try:
    ipaddress.ip_address(url)
    ip = 1
  except:
    ip = 0
  return ip



# 3.Checks the presence of @ in URL (Have_At)
def haveAtSign(url):
  if "@" in url:
    at = 1
  else:
    at = 0
  return at


# 4.Finding the length of URL and categorizing (URL_Length)
def getLength(url):
  if len(url) < 54:
    length = 0
  else:
    length = 1
  return length


# 5.Gives number of '/' in URL (URL_Depth)
def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth

# 6.Checking for redirection '//' in the url (Redirection)
def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1
    else:
      return 0
  else:
    return 0

# 7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpDomain(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1
  else:
    return 0


from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime

import requests
from bs4 import BeautifulSoup

def web_traffic(url):
    try:
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        rank = int(rank)
        if rank < 100000:
            return 1  # Phishing
        else:
            return 0  # Legitimate
    except (TypeError, urllib.error.URLError) as e:
        print(f"An error occurred: {e}")
        return 1



shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"
# 8. Checking for Shortening Services in URL (Tiny_URL)
import re
def tinyURL(url):
  match=re.search(shortening_services,url)
  if match:
    return 1
  else:
    return 0



# 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1            # phishing
    else:
        return 0


# 13.Survival time of domain: The difference between termination time and creation time (Domain_Age)
def domainAge(domain_name):
  creation_date = domain_name.creation_date
  expiration_date = domain_name.expiration_date
  if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
    try:
      creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if ((expiration_date is None) or (creation_date is None)):
      return 1
  elif ((type(expiration_date) is list) or (type(creation_date) is list)):
      return 1
  else:
    ageofdomain = abs((expiration_date - creation_date).days)
    if ((ageofdomain/30) < 6):
      age = 1
    else:
      age = 0
  return age


# 14.End time of domain: The difference between termination time and current time (Domain_End)
def domainEnd(domain_name):
  expiration_date = domain_name.expiration_date
  if isinstance(expiration_date,str):
    try:
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if (expiration_date is None):
      return 1
  elif (type(expiration_date) is list):
      return 1
  else:
    today = datetime.now()
    end = abs((expiration_date - today).days)
    if ((end/30) < 6):
      end = 0
    else:
      end = 1
  return end


import requests

# 15. IFrame Redirection (iFrame)
def iframe(response):
  if response == "":
      return 1
  else:
      if re.findall(r"[|]", response.text):
          return 0
      else:
          return 1


# 16.Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response):
  if response == "" :
    return 1
  else:
    if re.findall("", response.text):
      return 1
    else:
      return 0

# 17.Checks the status of the right click attribute (Right_Click)
def rightClick(response):
  if response == "":
    return 1
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      return 0
    else:
      return 1


# 18.Checks the number of forwardings (Web_Forwards)
def forwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1




# In[19]:


import whois

def is_phishing_domain(domain):
  try:

        # Query WHOIS information for the domain
    w = whois.whois(domain)
    if not w or "status" not in w.keys():
      return 1  # Phishing
    else:
      return 0  # Legitimate
  except Exception as e:
    print(f"An error occurred: {e}")
    return 1


# In[29]:


import whois

def display_whois_data(url):
    try:
      whois_data = whois.whois(url)
      print("Domain Name:", whois_data.domain_name)
      print("Registrar:", whois_data.registrar)
      print("Creation Date:", whois_data.creation_date)
      print("Expiration Date:", whois_data.expiration_date)
      print("Updated Date:", whois_data.updated_date)
      print("Name Servers:", whois_data.name_servers)
        # Add more WHOIS data fields as needed
    except Exception as e:
      print(f"Error fetching WHOIS data for {url}: {str(e)}")


# In[21]:


def trainexe(url):
  features=[]
  features.append(getDomain(url))
  features.append(havingIP(url))
  features.append(haveAtSign(url))
  features.append(getLength(url))
  features.append(getDepth(url))
  features.append(redirection(url))
  features.append(httpDomain(url))
  features.append(tinyURL(url))
  features.append(prefixSuffix(url))

  dns = 0
  try:
    domain_name = whois.whois(urlparse(url).netloc)
  except:
    dns = 1
  features.append(dns)
  #features.append(is_phishing_domain(url))
  features.append(web_traffic(url))
  features.append(1 if dns == 1 else domainAge(domain_name))
  features.append(1 if dns == 1 else domainEnd(domain_name))
  try:
    response = requests.get(url)
  except:
    response = ""
  features.append(iframe(response))
  features.append(mouseOver(response))
  features.append(rightClick(response))
  features.append(forwarding(response))
  whois_data = extract_whois_data(url)
  features.append(calculate_phishing_probability(whois_data))

  print(features)
  return features


# In[30]:


url=input("enter url:")
train=[]
train.append(trainexe(url))
feature_names = ['domain','Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
                 'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 'Domain_Age', 'Domain_End', 'whois', 'iFrame',
                 'Mouse_Over', 'Right_Click', 'Web_Forwards']
feature = pd.DataFrame(train, columns= feature_names)
X = feature[['domain','Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
                 'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 'Domain_Age', 'Domain_End', 'whois', 'iFrame',
                 'Mouse_Over', 'Right_Click', 'Web_Forwards']]
X = X.drop("domain", axis=1)
y_pred = model.predict(X)
if(y_pred==0):
  print("safe")
  display_whois_data(url)
else:
  print("suspisious")
  display_whois_data(url)
probability = model.predict_proba(X)[0][1]

