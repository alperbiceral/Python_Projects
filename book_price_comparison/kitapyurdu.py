from bs4 import BeautifulSoup
import requests
import sys

book_name = sys.argv[1]
headers = {'user-agent':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'}
response = requests.get(f'https://www.kitapyurdu.com/index.php?route=product/search&filter_name={book_name}', headers=headers)
if response.status_code != requests.codes.ok:
    sys.exit(3)

html_content = response.text
parser = BeautifulSoup(html_content, 'html.parser')

book_list = parser.find('div', id='product-table')
all_items = book_list.find_all('div', class_='product-cr')

books = []
for item in all_items:
    temp_dict = {}
    book_title = item.find('div', class_='name')
    product_name = book_title.span.text.strip()
    price = item.find('span', class_='value')
    if price == None:
        continue
    else:
        price = float(price.text.strip().replace(',', '.'))
    book_link = book_title.a['href']
    temp_dict = {'product_name':product_name, 'price':price, 'book_link':book_link}
    books.append(temp_dict)

sorted_books = sorted(books, key=lambda d: d['price'])