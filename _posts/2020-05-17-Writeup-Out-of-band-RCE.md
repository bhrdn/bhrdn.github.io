---
layout: post
title: Writeup Out of band RCE
---

## Challange
<blockquote class="twitter-tweet"><p lang="en" dir="ltr">Booom, 100 likes reached and you can review source codes:<a href="https://t.co/IPG8OI9hNT">https://t.co/IPG8OI9hNT</a><br><br>Next tip: when reached 120 like! 🕵️‍♂️</p>&mdash; VULLNERABILITY (@VULLNERAB1337) <a href="https://twitter.com/VULLNERAB1337/status/1260647839467663361?ref_src=twsrc%5Etfw">May 13, 2020</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script> 

## Whitebox Testing
- Source code : http://lab.takeover.host/source.zip

![image](https://user-images.githubusercontent.com/13828056/82134970-dac96680-9827-11ea-8f12-d9b1fd9bbaf9.png)
Didapati pemanggilan fungsi system pada line 43, yang bertujuan untuk menyimpan $content kedalam $filename

Sekarang lakukan pengecekan pada variable getname, tablename, price, receiptcode yang nantinya akan di masukkan kedalam variable content.

- variable getname
![image](https://user-images.githubusercontent.com/13828056/82135108-07ca4900-9829-11ea-8460-98e2b442455e.png)

Dari sini sebenarnya sudah terlihat celah code injection, jika kita tidak menggunakan cookie name dan langsung melakukan request POST dengan query name, dikarenakan pada saat set cookie name terdapat fungsi clear yang akan menghapus beberapa karakter penting untuk melakukan code injection.

![image](https://user-images.githubusercontent.com/13828056/82135179-cf773a80-9829-11ea-80f4-44db1099b6af.png)

- variable tablename
![image](https://user-images.githubusercontent.com/13828056/82135327-b40d2f00-982b-11ea-80f4-565d108f5db3.png)

Sama seperti variable getname sebelumnya, pada variable tablename kita bisa langsung melakukan request GET dengan query table, untuk melakukan code injection karna tidak ada filter apapun.

- variable price

![image](https://user-images.githubusercontent.com/13828056/82135344-efa7f900-982b-11ea-8cc3-56dce417f033.png)

Hanya constant value antara "80$" dan "350$" dan tidak ada celah untuk di eksploitasi

- variable receiptcode
![image](https://user-images.githubusercontent.com/13828056/82135375-3c8bcf80-982c-11ea-8493-77e9fb9d23d4.png)

Hanya dimanfaatkan untuk random number filename dan tidak ada celah untuk di eksploitasi

## Conclusion
Dari analisa diatas didapati jika terdapat 2 vuln variable name dan tablename, untuk skema exploitnya antara lain sebagai berikut ini.

- name : "Reserved to: **; uname -a ;** \n\n [SNIP]"
- tablename : "Reserved to: {name}\n\nTable: **\`uname -a\`** \n\n [SNIP]"

## Proof name
![image](https://user-images.githubusercontent.com/13828056/82135563-5cbc8e00-982e-11ea-96cf-73a82237fee8.png)

## Proof tablename
![image](https://user-images.githubusercontent.com/13828056/82135636-0c91fb80-982f-11ea-8aff-af0162cf831b.png)
![image](https://user-images.githubusercontent.com/13828056/82135649-3b0fd680-982f-11ea-9a9b-61313f2c9319.png)

## Grab flag
```bash
find / -name flag.txt | xargs cat 2>/dev/null
```
![image](https://user-images.githubusercontent.com/13828056/82135719-123c1100-9830-11ea-9ed4-a61980d87488.png)