# Memzilla

### Catégorie :
Forensic

### Flag : 
```mctf{OhMYG0D_F0r3n5iccc_i5_s0_CO0OOO00OO0OL!!!!!}```

### Auteur du challenge :
kacheriwka

### Auteur du WU :
moi(ScottKushy)

### Desc : 
Gave a friend to google from his laptop, after sitting down he had a fit of laughter. He won't answer my legitimate questions. Help me figure it out, I'm not going to sleep until I figure it out.... (traduit)

## Write Up :

Dans ce challenge, l'énoncé et le fichier nous évoque déja pas mal ce que nous devons faire (déja le fait de pas dormir) et le fait qu'il va falloir faire du forensic de mémoire (ouais en français c'est pas ouf), en premier lieu voila ce que j'ai tenté : 
### Memprocfs 
via ce git la : 

https://github.com/evild3ad/MemProcFS-Analyzer

alors ce script est vraiment bien niveau analyse et infos de manière globale, j'ai vraiment presque tout obtenu sur l'image en question et en automatique (si c'est pas beau) mais dans ce challenge, il ne nous servira vraiment à rien malheuresement :( (1h d'installation pour rien).
Il va donc bien falloir suivre à la lettre l'énoncé : Navigateur (ici chrome), donc dump le navigateur (pas précis mais je vais détailler ça juste en dessous). Pour ça rien de tel que notre bon vieil ami : 
### Volatility !

Maintenant, deux choix s'offrent à nous, soit on trouve un moyen de dump l'executable, on cherche l'historique, on le décrypte à la main (perso j'ai pas trouvé de moyen vraiment concluant, juste des moyens de dump par ci par la, le cache et l'historique) ou alors the easy way (celle que j'ai choisie évidemment car je suis un feignant légendaire), on utilise un plugin et c'est la qu'intervient : 
### Chromehistory ! (développé par superponible)

https://github.com/superponible/volatility-plugins/blob/master/chromehistory.py

(hors contexte mais je n'avais pas volatility 2, le plugin ne marchait que sur vol2, j'ai donc bien galéré pendant 2h à l'installer sur WSL (très smart d'utiliser wsl pour ce genre de chall bravo ! 🤦)).
une fois volatility d'installé il faut maintenant s'attaquer à l'installation de ce plugin obscur : 
On crée un dossier plugins/ sur la racine de vol2 :
![image_2023-11-05_155627452](https://github.com/xTommyBoy/Memzilla/assets/66128183/315754a8-2f8c-4c39-a3b2-8febc59a2737)

On y met le plugin en question :

![image_2023-11-05_155828939](https://github.com/xTommyBoy/Memzilla/assets/66128183/190b64f9-da71-437a-bcfa-aa1b3e60c558)
<p> (et on y met sqlite helper que j'ai mis 30 ans à trouver car non ce n'est pas une lib python mais un plugin crée aussi par superponible qu'il faut aller chercher ert glisser dedans) </p>

On initialise les plugins : ```python2 vol.py --plugins=./plugins -h```

![image_2023-11-05_160815503](https://github.com/xTommyBoy/Memzilla/assets/66128183/2c36ff2b-9acf-470b-a48c-55a10c6fc338)

on peut maintenant voir que le plugin est visible et fonctionnel, d'ailleurs à propos de ce plugin, il ne fait pas que chercher l'historique comme on peut le voir dans la liste, c'est un script all in one qui fait tout un tas de choses (une sorte de couteau suisse).

On lance maintenant le plugin (qui detecte automatiquement le profil de l'image) : ```python2 vol.py --plugins=plugins/ -f memzilla3.mem chromehistory```
on obtiens ceci : 

![image_2023-11-05_161310908](https://github.com/xTommyBoy/Memzilla/assets/66128183/a94c2ae8-2243-4a86-a511-8f568c95fe66)

et si on regarde bien on peut voir que l'utilisateur (Denis) à cherché un truc en base64 : ```=MjcwY0XEBzRZ1EaPtnZ0NWb```

on décode le base64 et.... ça marche pas ? Mmh regardons plus attentivement les résultats du plugin : ```khHdsyAaST2=v?hctaw/moc.ebutuoy.www//:sptth```

on peut voir dans l'un des résultats que c'est à l'envers, et si on éssayait de mettre notre base64 à l'envers nous aussi : ```bWN0ZntPaE1ZRzBEX0YwcjM=```

et la TA-DAM ! on obtiens...qu'une partie du flag :( (c'est déja ça sa nous montre que c'est bien la bonne voie) : ```mctf{OhMYG0D_F0r3``` .

Bon à partir de la, j'ai coincé pendant bien 1h30-2h, j'ai cherché via les autres liens, de les remettre à l'endroit, copier, couper, coller, mais rien. Sauf, une piste qui à attiré mon attention, 
l'utilisateur à cherché : ```how to change 1356x649``` . En cherchant juste avant toutes ces étapes j'avais énuméré un scan des processus et j'y ai vu "mspaint" juste après chrome, donc je refait la commande :
```python2 vol.py -f memzilla3.mem --profile=Win7SP1x64 pslist```

![image](https://github.com/xTommyBoy/Memzilla/assets/66128183/278d62cd-353a-47ab-9d39-e95dea6608e1)

et la dans un élan de détermination, je me dis peut être que le flag est caché dans l'image que l'utilisateur est entrain de faire, du coup je dump le processus de ce pas :

```python2 vol.py -f memzilla3.mem --profile=Win7SP1x64 memdump -p 3728 -D .```
(-p est pour définir le pid qu'on veut dump et -D pour définir le directory dans le quel on veut save le dump ici à la racine de vol2).

Le dump ce save et la que du garbage data de 256 mo. J'ai donc cherché sur google un moyen de récupérer l'image provenant de paint via un dump de volatility, j'ai pu voir que gimp avait une fonction géniale qui est d'afficher du raw data en image.
On renomme le fichier dump ici ```3728.dmp``` en ```3728.data``` et on lance gimp via ce gros tas de garbage data.

### Guessing alert ⚠️ : 
Ce passage est relativement guessy car il va falloir utiliser le défilement de gimp un peu au pif, jusqu'a trouver la fenêtre de l'image en question.

Bref, on définit la taille que Denis (l'utilisateur) à cherché sur google, on met l'image en ARGB et on défile jusqu'à prier pour tomber sur quelque chose : 

![image](https://github.com/xTommyBoy/Memzilla/assets/66128183/aaacee40-9c78-4aed-815f-65a96b8daca8)

On défile, on défile et au bout de quelques minutes TA-DAM ! on tombe sur la fenêtre en question (et le scan de ftkimager).
On à donc ici notre deuxieme partie du flag : ```n5iccc_i5_s0_```.

Il ne reste du coup surement plus que la dernière partie du flag, si on utilise la logique de la partie précédente du flag (qui est de dumper, à gauche, à droite ce qui pourrait être graphique ou affichable) on peut voir dans la liste juste avant, qu'il y'avait aussi ```notepad ++``` d'ouvert
je décide donc de le dumper aussi : 

```python2 vol.py -f memzilla3.mem --profile=Win7SP1x64 memdump -p 3852 -D .```

on obtiens encore, un gros tas de garbage data, c'est à partir de la que l'un de mes outils préférés si ce n'est ma madeleine de proust entre en action ! : 
### Detect-It-Easy 
(le git : https://github.com/horsicq/Detect-It-Easy)

on glisse le dmp sur le string searcher (plus stylé en anglais) : 
![image](https://github.com/xTommyBoy/Memzilla/assets/66128183/34363660-e442-4175-84de-f32d190536d1)

on y met un filtre de close brackets (car logiquement c'est la fin du flag) : 

![image](https://github.com/xTommyBoy/Memzilla/assets/66128183/9c3505f3-cd6d-456a-8fd8-b04d9aa68e2b)

Et voila !!! on à la dernière partie du flag ! 

Ce qui nous donne au final : ```mctf{OhMYG0D_F0r3n5iccc_i5_s0_CO0OOO00OO0OL!!!!!}```

### Afterwords : 

Ce chall à été super instructif dans mon apprentissage sur ce magnifique tool qu'est volatility, de l'installation du tool, de l'installation des plugins, jusqu'au dumps de fichiers. Au final on peut voir que les dumps peuvent être ouvrables et utilisables dans tout les cas (d'une manière un peu barbare je le conçoit mais d'une manière quand même).

### Merci d'avoir lù ! .
