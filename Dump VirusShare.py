import requests
import pandas

FinalList = []
TempList = []
incrementor = 0
urladdonLen = 5
ext = ".md5"


def fetchVSURL():
    global incrementor
    baseurl = "https://virusshare.com/hashfiles/VirusShare_"
    addonLen = urladdonLen - len(str(incrementor))
    finalurl = baseurl + addonLen * "0" + str(incrementor) + ext
    return finalurl


for i in range(99999):
    finalURL = fetchVSURL()
    print("Working on ---->", finalURL)
    if requests.get(finalURL).status_code == 200:
        print("Valid Response Found. Streaming Hashes!", requests.get(finalURL).status_code)
        r = requests.get(finalURL, stream=True)
        rawtext = r.text
        hashes = rawtext.split("\n")
        for hash in hashes[6:]:
            if len(hash) < 32:
                pass
            else:
                TempList.append(hash)
    else:
        break
    incrementor += 1

print("Please Wait. Working on the CSV")
for i in TempList:
    FinalList.append(i)

df = pandas.DataFrame(FinalList, columns=["Hashes"])
try:
    df.to_csv('GFG.csv')
    print("Successfully Created CSV!")
except Exception as e:
    print("Failed to Write to CSV.", e)