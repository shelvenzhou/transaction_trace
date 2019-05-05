from lxml import html
import requests

url_template = "https://etherscan.io/find-similar-contracts?a=%s&lvl=5"

address = "0x07804007e596d60d3f826066d4e93079e8a5732b"


def main():
    page = requests.get(url_template % address)
    tree = html.fromstring(page.content)
    address_xpath = '//div[@id="ContentPlaceHolder1_divsearchresults"]/div/table/tr/td[4]/a/span/text()'

    for contract_addr in tree.xpath(address_xpath):
        print(contract_addr)
    # import IPython; IPython.embed()


if __name__ == "__main__":
    main()
