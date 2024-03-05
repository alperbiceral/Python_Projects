from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys

options = Options()
# for headless usage (browser is not opened to the user)
#options.add_argument('--headless')
#options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')
options.add_argument('--disable-blink-features=AutomationControlled') # to evade the detection as a bot
driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

driver.get("https://www.m5bilisim.com/tr/on-parmak/hiz-testi/")

try:
    word_list = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "satir")))
    words = word_list.find_elements(By.TAG_NAME, "span")

    input_bar = driver.find_element(By.ID, "yaziyaz")
    for word in words:
        input_bar.send_keys(word.text)
        input_bar.send_keys(Keys.SPACE)
finally:
    driver.quit()