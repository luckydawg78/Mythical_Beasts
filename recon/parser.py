from bs4 import BeautifulSoup

def parse_html(html_content):
    targets = []
    with open(html_content, 'r') as f:
        soup = BeautifulSoup(f, 'html.parser')
        for row in row[1:]:
            cols = [c.text.strip() for c in row.find_all('td')]
            if len(cols) >= 3:
                ip, port, service = cols[0], cols[1], cols[2]
                targets.append({"ip": ip, "services": [service]})
    return targets