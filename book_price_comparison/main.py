import dnr
import amazon
import kitapyurdu
import csv

def main():
    dnr_books = dnr.sorted_books
    amazon_books = amazon.sorted_books
    kitapyurdu_books = kitapyurdu.sorted_books

    all_books = dnr_books + amazon_books + kitapyurdu_books

    all_sorted_books = sorted(all_books, key=lambda d: d['price'])

    with open('book_comparison.csv', 'w', newline='') as output_file:
        output_writer = csv.DictWriter(output_file, ['product_name', 'price', 'book_link'])
        output_writer.writeheader()
        for book in all_sorted_books:
            output_writer.writerow(book)

if __name__ == "__main__":
    main()