# Securitatea-Informatiei-HW1
#Cerinta
mplementati o infrastructura de comunicatie ce foloseste AES pentru criptarea traficului intre doua noduri A si B cu urmatoarele caracteristici:

Context de initializare. Se considera un nod KM (key manager) care detine trei chei K1, K2 si K3. K1 este asociata cu modul de operare CBC. K2 este asociata cu modul de operare OFB. K3 este utilizata pentru criptarea cheilor K1 si K2. K3 este de asemenea detinuta din start si de nodurile A si B.

Faza de initializare - Schimbul de chei. Pentru a initia o sesiune de comunicare securizata nodul A trimite un mesaj catre B in care comunica modul de operare (CBC sau OFB) si similar cere nodului KM cheia corespunzatoare. Cheia ceruta (K1 sau K2 in functie de modul de operare) este criptata ca un singur bloc cu AES de KM folosind cheia K3 si trimisa ca raspuns nodului A, ce o va trimite mai departe nodului B. A si B vor decripta cheia (K1 sau K2) la primire pentru a incepe comunicarea.

Faza de transport - Comunicare securizata. Dupa ce trimite cheile catre B, nodul A incepe sa trimita catre B continutul unui fisier criptat pe blocuri folosind modul selectat.

Faza de reimprospatare a cheii - Key refresh. Periodic, dupa trimiterea de q blocuri unde q se considera un parametru global setat in sistem cunoscut de toate nodurile, nodul A reinitializeaza protocolul de obtinere a cheii din faza de initializare. Nodul KM va genera astfel periodic o cheie noua in functie de cerere (K1 sau K2) care va fi distribuita similar cu descrierea de mai sus, dupa care comunicarea este reluata.

Pentru testare se va folosi un fisier ce va fi trimis de la A la C, suficient de mare pentru a exista macar o regenerare de chei pe parcurs.

Se accepta orice limbaj si folosirea oricarei librarii pentru implementare. AES poate fi folosit ca algoritm de criptare pus la dispozitie de orice librarie criptografica. Modul de operare insa (CBC si OFB) se cere sa fie implementat in cadrul temei. Nu se cere rezolvarea de eventuale probleme de sincronizare intre noduri, interfata pentru noduri, sau un anumit protocol de comunicare.
