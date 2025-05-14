# SuidyRevenge - HackMyVM (Hard)
 
![suidy.png](suidy.png)

## Übersicht

*   **VM:** SuidyRevenge (obwohl der Link "suidy" lautet, wird im Text "SuidyRevenge" verwendet)
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=suidy)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 17. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/suidy_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "SuidyRevenge"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Entdeckung von Benutzer-Credentials (`theuser:different`) in einem HTML-Kommentar auf dem Webserver (Port 80). Dies ermöglichte den initialen SSH-Login als `theuser`. Die User-Flag wurde in dessen Home-Verzeichnis gefunden. Die Privilegieneskalation erfolgte in mehreren Stufen: Zuerst wurde ein SUID/SGID-Binary (`/home/suidy/suidyyyyy`) gefunden, das bei Ausführung eine Shell als Benutzer `suidy` gewährte. Als `suidy` wurde eine Notiz (`note.txt`) gefunden, die erklärte, dass ein Root-Skript regelmäßig das SUID-Bit auf `suidyyyyy` setzt, aber dabei die Dateigröße prüft. Der finale Schritt zur Root-Eskalation bestand darin, einen eigenen C-Code für eine Root-Shell direkt auf der Zielmaschine zu kompilieren, das ursprüngliche `suidyyyyy`-Binary damit zu überschreiben und (wahrscheinlich durch das Root-Skript) das SUID-Bit erneut setzen zu lassen. Die Ausführung des modifizierten `suidyyyyy` führte dann zu einer Root-Shell.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `vi` / `nano`
*   `curl`
*   `ssh`
*   `cat`
*   `sudo`
*   `find`
*   `ls`
*   `cd`
*   `gcc`
*   `mv`
*   `chmod`
*   `id` (implizit)
*   `pwd`
*   `grep`
*   `wget`
*   `python3`
*   Standard Linux-Befehle

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "SuidyRevenge" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.155`).
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH - OpenSSH 7.9p1) und 80 (HTTP - Nginx 1.14.2).
    *   `gobuster` auf Port 80 fand nur `/index.html`.
    *   Manuelle Untersuchung des Quellcodes von `/index.html` offenbarte einen HTML-Kommentar mit den Credentials `theuser:different` und einen Hinweis auf ein Verzeichnis `/supersecure` (letzteres spielte im weiteren Verlauf keine Rolle).

2.  **Initial Access (SSH Login):**
    *   Erfolgreicher SSH-Login als `theuser` mit dem Passwort `different` (`ssh theuser@192.168.2.155`).

3.  **Privilege Escalation (von `theuser` zu `suidy`):**
    *   `sudo -l` für `theuser` zeigte keine Sudo-Rechte.
    *   User-Flag `HMVbisoususeryay` in `/home/theuser/user.txt` gelesen.
    *   `find / -perm -4000 ...` identifizierte ein SUID/SGID-Binary `/home/suidy/suidyyyyy` (Besitzer `root`, Gruppe `theuser`, `rwsrws---`).
    *   Ausführung von `/home/suidy/suidyyyyy` als `theuser` führte zu einer Shell als Benutzer `suidy`.

4.  **Privilege Escalation (von `suidy` zu `root`):**
    *   `sudo -l` für `suidy` scheiterte an unbekanntem Passwort.
    *   Lesen von `/home/suidy/note.txt` enthüllte, dass ein Root-Skript regelmäßig das SUID-Bit auf `/home/suidy/suidyyyyy` setzt, aber dabei die Dateigröße prüft.
    *   Erstellung eines C-Programms (`ben.c`) direkt auf der Zielmaschine als `suidy`, das `setuid(0)` aufruft und eine Bash-Shell startet:
        ```c
        int main(void){
           setuid(0);
           system("/bin/bash");
        }
        ```
    *   Kompilieren des C-Programms auf dem Ziel mit `gcc ben.c -o ben`.
    *   Überschreiben des ursprünglichen `/home/suidy/suidyyyyy`-Binaries mit dem neu kompilierten `ben`-Binary (`mv ben suidyyyyy`).
    *   Das SUID-Bit wurde entweder durch das Root-Skript erneut gesetzt oder manuell mit `chmod 4755 suidyyyyy` (obwohl die Berechtigung dafür als `suidy` fraglich ist; das Root-Skript ist wahrscheinlicher).
    *   Ausführung des modifizierten `/home/suidy/suidyyyyy` als `suidy` startete eine Shell mit Root-Rechten.
    *   Root-Flag `HMVvoilarootlala` in `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Credentials im Quellcode:** Ein HTML-Kommentar enthielt gültige Benutzer-Credentials.
*   **Benutzerdefiniertes SUID/SGID-Binary:** Ein Binary (`/home/suidy/suidyyyyy`) mit SUID-Root und SGID-Benutzer-Rechten ermöglichte einen lateralen Wechsel bzw. eine erste Privilegieneskalation.
*   **Unsicherer Mechanismus zur SUID-Bit-Wiederherstellung:** Ein Root-Skript, das SUID-Bits setzt, aber eine umgehbare Größenprüfung durchführt, wurde zum Hauptangriffsvektor für die Root-Eskalation.
*   **Kompilieren auf dem Zielsystem:** Das Erstellen und Kompilieren des Exploits direkt auf der Zielmaschine umging die Größenprüfung des SUID-wiederherstellenden Skripts.
*   **SUID Exploit:** Ein einfaches C-Programm mit `setuid(0)` und `system("/bin/bash")` wurde verwendet, um die durch das SUID-Bit erlangten Root-Rechte auszunutzen.

## Flags

*   **User Flag (`/home/theuser/user.txt`):** `HMVbisoususeryay`
*   **Root Flag (`/root/root.txt`):** `HMVvoilarootlala`

## Tags

`HackMyVM`, `SuidyRevenge`, `Hard`, `SUID Exploitation`, `Credentials in Comments`, `Lateral Movement`, `C Exploitation`, `Linux`, `Privilege Escalation`
