import sys,os
import urllib,urllib2
import time
import json

def vt_scan(url):
    params = {'apikey': '1c61351694700b80190bcf07f3d043be0d656591919ad4f5a81836b3ae76bb87', 'url':url}
    req = urllib2.Request('https://www.virustotal.com/vtapi/v2/url/scan', data=urllib.urlencode(params))
    response = urllib2.urlopen(req) 
    the_page = response.read()
    with open('resp_json.log','ab') as fh:
        fh.write(the_page+'\n')

    print 'Url scanned successfully!'

def vt_report(url):
    print 'Now acquiring the report...'

    # sleep 15 to control requests/min to API. Public APIs only allow for 4/min threshold.
    time.sleep(15)

    params = {'apikey': '1c61351694700b80190bcf07f3d043be0d656591919ad4f5a81836b3ae76bb87', 'resource':url}
    req = urllib2.Request('https://www.virustotal.com/vtapi/v2/url/report', data=urllib.urlencode(params))
    response = urllib2.urlopen(req) 
    the_page = response.read()
    with open('resp_json.log','ab') as fh:
        fh.write(the_page+'\n')

    response_dict = json.loads(the_page)
    scans = response_dict.get('scans', {})
    detected_key = []
    for key in scans:
        if True == scans[key]["detected"]:
            detected_key.append(key)
    return detected_key

# def batch_query(urls):
#     # urls should be a list
#     with open('resp_json.log','wb') as fh:
#         fh.write('')
#     for url in urls:
#         print 'Now scanning url: '+url+'\n'
#         vt_scan(url)
#         det = vt_report(url)
#         if det:
#             print 'Detected in: '+';'.join(vt_report(url))
#         else:
#             print 'Detected in no scanner!'

def print_usage():
    print """
Usage:
    python vt_query.py url
    """

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print_usage()
        exit(-1)

    url = sys.argv[1]
    print 'Now scanning url: '+url
    vt_scan(url)
    det = vt_report(url)
    if det:
        print 'Detected in: '+';'.join(vt_report(url))
    else:
        print 'Detected in no scanner!'
