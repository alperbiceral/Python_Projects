from bs4 import BeautifulSoup
import requests
import sys

book_name = sys.argv[1]
response = requests.get(f'https://www.dr.com.tr/search?q={book_name}&redirect=search')

if response.status_code != requests.codes.ok:
    sys.exit(1)

html_content = response.text
parser = BeautifulSoup(html_content, 'html.parser')
all_items = parser.find('div', class_='facet__products-list js-facet-product-list')
items = all_items.find_all('div', class_='prd-main-wrapper')
books = []
for item in items:
    product_name = item.find('div', class_='prd-infos').text.strip().replace('\n', '| ')
    price = float(item.find('div', class_='prd-price').text.strip()[:-3].replace(',', '.'))
    book_link = "https://www.dr.com.tr" + item.find('h3').a['href']
    temp_dict = {'product_name':product_name, 'price':price, 'book_link':book_link}
    books.append(temp_dict)

sorted_books = sorted(books, key=lambda d: d['price'])