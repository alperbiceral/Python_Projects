from bs4 import BeautifulSoup
import requests
import sys

book_name = sys.argv[1].replace(' ', '+')
headers = {'user-agent':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'}
response = requests.get(f'https://www.amazon.com.tr/s?k={book_name}&i=stripbooks', headers=headers)
if response.status_code != requests.codes.ok:
    sys.exit(2)

html_content = response.text

parser = BeautifulSoup(html_content, 'html.parser')
items = parser.find_all('div', class_='sg-col-20-of-24 s-result-item s-asin sg-col-0-of-12 sg-col-16-of-20 sg-col s-widget-spacing-small sg-col-12-of-16')

books = []
for item in items:
    try:
        temp_dict = {}
        book_title = item.find('h2', class_='a-size-mini a-spacing-none a-color-base s-line-clamp-2')
        product_name = book_title.text.strip()
        price = float(item.find('span', class_='a-price').find('span', class_='a-offscreen').text.strip()[:-3].replace('.', '').replace(',', '.'))
        book_link = 'https://www.amazon.com.tr' + book_title.a['href']
        temp_dict = {'product_name':product_name, 'price':price, 'book_link':book_link}
        books.append(temp_dict)
    except AttributeError as attrError:
        continue

sorted_books = sorted(books, key=lambda d: d['price'])