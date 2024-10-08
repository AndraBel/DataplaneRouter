Belceanu Andra-Maria
321CA

# <span style="color:orange"> Tema 1 PCom </span>



Pentru implementarea routerului, am folosit urmatorul workflow:

## <span style="color:lightskyblue">Route table & procesul de dirijare
1.   Am initializat tabela de rutare statica pe care am sortat-o folosind
qsort cu o functie de compare care sorteaza in functie de conditia pentru
LPM, iar in caz de egalitate, se sorteaza crescator dupa masca. Am ales sa
sortez tabela deoarece pentru a cauta best route-ul am implementat o cautare
binara ce are o complexitate de O(logn), care este mult mai eficienta decat o
cautare liniara.

## <span style="color:greenyellow">ARP

2. Am intializat tabela de ARP. Pentru implementarea protocolului de ARP am
urmat acesti pasi:
    * cand routerul primeste ARP REQUEST cu una dintre adresele ip a
interfetelor sale, trimite ARP REPLY cu adresa mac corespunzatoare interfetei
    *  cand se primeste un ARP REPLY se completeaza tabela de arp daca adresa
mac nu se gaseste in arp table, dupa asta se verifica daca exista pachete in
coada, in caz afirmativ acestea se scot, iar daca exista toate datele necesare,
cum ar fi IP sursa, IP destinatie, MAC surs, MAC destinatie, se continua cu
procesarea si trimiterea pachetului respectiv.

## <span style="color:magenta">IP ICMP 
3. Cand se primeste un pachet pe una din interfete, prima data se verifica
daca pachetul este un ICMP echo destinat routerului, caz pentru care se trimite
un ICMP echo reply inapoi la cel care a trimis acel pachet. Urmeaza sa se
verifice checksumul, iar daca acesta e gresit se da drop la pachet, apoi se
verifica si ttl ul si se trimite un ICMP time exceeded, in caz ca a ajuns la 0.
Se cauta in tabela de rutare un best route, iar daca acesta nu exista, trimit 
ICMP destination unreacheable. Scad ttl ul si actualizez checksumul. Urmeaza
modificarea antetului de ethernet, cu adresa destinatiei mac gasita in tabla
de arp, pentru cazul in care nu exita adresa mac in tabela arp, se baga
pachetul in coada si se face un ARP REQUEST pentru aflarea adresei mac 
respective. Daca adresa mac a fost gasita in tabela arp, se completeaza
aferent headerul de ethernet pentru trimiterea mai departe a pachetului
cu adresa mac a destinatiei si adresa mac a routerului.