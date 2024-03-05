import requests
from bs4 import BeautifulSoup

html_contents = []
for page_no in range(1, 17):
    response = requests.get(f"https://news.ycombinator.com/?p={page_no}")
    html_contents.append(response.content)

with open("test.txt", "w") as test_file:
    for html_content in html_contents:
        
        parser = BeautifulSoup(html_content, "html.parser")        
        headings = parser.find_all("tr", class_="athing")
        
        for heading in headings:
        
            test_file.write(heading.text + "\n")
            link = heading.find("span", class_="titleline").a["href"]
            test_file.write(link + "\n\n")