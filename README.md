# Parb.Darb6marts
Teorijas jautajumi:
1) Salt ir nejauša vērtība, kas tiek pievienota parolēm pirms to "hashēšanas". Ar tā palīdzību pat identiski paroles datu bāzē būs ar atšķīrigiem hashem.
2) Paroles plaintext formā var viegli izlasīt, ja kāds iegūst piekļuvi failam. Un tāpēc paroles jāsāglabā hash formā.
3) Brute-force uzbrukums ir metode, kur hakers izvēlas paroles kombinācijas un atrod vajadzīgo. Lockout palīdz izvairīties no šiem uzlaušanas mēģinājumiem, jo bloķē lietotāju pēc noteiktā mēģinājumu skaita.
4) hmac.compare_digest veic salīdzinājumu pastāvīgā laikā. Tas novērš laika uzbrukumu, kurā hakers var noteikt paroli pēc salidzinājuma laika. == var atgriezt rezultātu ātrāk, ja pirmie simboli nesakrīt.
5) Pirma prakse ir izmantot uzticamu paroles hashēšanas algoritmu kā argon2. Otra prakse ir 2FA(divu faktoru autentifikācija), kas arī prasa pārbaudes kodu.
