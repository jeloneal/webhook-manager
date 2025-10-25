
import requests

# HTML-Datei von der URL laden
url = "https://ppl-ai-code-interpreter-files.s3.amazonaws.com/web/direct-files/83f57d75cda83f04cc89e40b516c6eb7/89756461-451b-4fc1-b4ae-cd2d44be7968/index.html"
response = requests.get(url)

# Speichern
with open('index.html', 'w', encoding='utf-8') as f:
    f.write(response.text)

print(f"HTML-Datei geladen: {len(response.text)} Zeichen")
print("Erste 500 Zeichen:")
print(response.text[:500])
