# dmarc-reports
DMARC report agregator


How to use:
1. export all DMARC report e-mails using Google Takeout (.mbox file)
2. run 'extract-attachments.py [filename].mbox' (mostly .zip compressed reports)
3. extract the reports (.xml files)
4. rename the reports to 000.xml .. (NUM_REPORTS-1).xml, set the NUM_REPORTS variable in dmarc-parser.py
5. run 'dmarc-parser.py' (generates dmarc_stats.txt)
6. ???
7. PROFIT!


The parser provides a tree in the form 'auth. domain -> IP -> number of pass / fail results'.
