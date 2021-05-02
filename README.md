# Macaque (crypto, 50)



## Description du problème

Ce challenge est le premier de la section crypto du FCSC 2021.

Au lancement le programme nous donne 3 commandes: 
```py
def usage():
    print("Commands are:")
    print("|-> t: Authenticate a message")
    print("|-> v: Verify a couple (message, tag)")
    print("|-> q: Quit")
```

On remarque donc qu'on est face à un système d'authentification et qu'il faudra certainement forger une fausse signature.

On s'intéresse alors à la partie qui crée la signature:

```py
class Macaque():
    def __init__(self, k1, k2):
        self.k1 = k1
        self.k2 = k2
        self.bs = AES.block_size
        self.zero = b"\x00" * self.bs

    def tag(self, m):
        m = pad(m, self.bs)
        print(m)
        c1 = AES.new(self.k1, AES.MODE_CBC, iv = self.zero).encrypt(m)
        c2 = AES.new(self.k2, AES.MODE_CBC, iv = self.zero).encrypt(m)
        return c1[-self.bs:] + c2[-self.bs:]

    def verify(self, m, tag):
        return self.tag(m) == tag
```

On peut voir que la signature est créée à partir de deux chiffrements ( donc deux clés différentes ) avec AES-CBC du message ( avec padding ) dont on ne prend que le dernier bloc. On a donc affaire à du CBC-MAC.

En cherchant un peu on trouve que CBC-MAC est sensible à une attaque par taille de message. En effet le fait que le programme ne prenne que le dernier bloc du chiffré nous permet de modifier le début du message sans en changer la signature.

Le programme ajoute cependant une contrainte supplémentaire, nous n'avons le droit qu'à trois signatures pour créer notre fausse signature.

```py
if cmd == 't':
            if len(S) < 3:

                print("Message (hex):")
                message = bytes.fromhex(input(">>> "))
                if not len(message):
                    exit(1)

                tag = singe.tag(message)
                print(f"Tag (hex): {tag.hex()}")
                S.add(message)
            else:
                print("Error: you cannot use this command anymore.")
```

Cela à cause de ce bout de code qui ajoute chaque message signé à un set et compare la taille du set à 3 à chaque signature et renvoie une erreur si la taille est supérieure.

Ce n'est pas un problème puisque notre attaque ne nécessite normalement que 2 messages. Cependant contrairement à un CBC-MAC ce programme utilise 2 chiffrés nous allons donc devoir utiliser un 3ème message pour créer notre fausse signature.

## Description de l'attaque

Pour cette attaque nous allons exploiter le fait que seul le dernier bloc est pris en compte.

On va donc envoyer un message de 16 octets se terminant par **\x01** en l’occurrence le message doit être envoyé en hexadécimal donc j'ai choisi **61616161616161616161616161616101** :
```
>>> t
Message (hex):
>>> 61616161616161616161616161616101
Tag (hex): bb1e34db8d180f990bbd7b8f10b70269d63a8a102c800b75dccabf937ef62216
```

Nous connaissons le tag de notre message. Maintenant décomposons le :

Pour rappel notre message à été paddé et est donc devenu **6161616161616161616161616161610110101010101010101010101010101010**

Il est donc chiffré en deux blocs.

Première partie du tag:
bb1e34db8d180f990bbd7b8f10b70269

Cette partie est le deuxième bloc de notre message chiffré.

Petit rappel sur AES-CBC:

![Mode CBC](https://upload.wikimedia.org/wikipedia/commons/thumb/4/42/Schema_CBC.svg/1920px-Schema_CBC.svg.png)
Le bloc chiffré #1 est xoré avec le deuxième bloc du message avant d'être chiffré.

Nous voulons avoir une signature qui a le même dernier bloc chiffré que le bloc chiffré #2 actuel avec un message différent, pour ceci il nous faut le bloc chiffré #1 pour connaitre l'input qui a donné le bloc chiffré #2.

Notre premier bloc de message étant **61616161616161616161616161616101** nous allons profiter du padding du message pour envoyer **616161616161616161616161616161** qui va être paddé avec **01** ( selon le standard de padding de AES ), le programme va donc nous renvoyer le chiffré de notre premier bloc:

```
>>> t
Message (hex):
>>> 616161616161616161616161616161
Tag (hex): 07c9d338c75ef768daa6136bfceef685362797629fe505aaf93b644810e7d89a
```

Nous savons donc maintenant que notre premier bloc chiffré est **07c9d338c75ef768daa6136bfceef685**

On a donc bb1e34db8d180f990bbd7b8f10b70269 = Enc(07c9d338c75ef768daa6136bfceef685 **⊕** 10101010101010101010101010101010)

Nous connaissons maintenant tous les éléments pour recréer notre première partie de tag.

L'attaque étant basée sur la longueur du message notre message va être un bloc plus long.

Nous allons prendre notre premier bloc de message dont nous connaissons le chiffré puis y concaténer son chiffré xoré avec lui même.

L'explication est qu'en xorant le message avec son chiffré nous allons inverser le xor qui intervient dans le chiffrement du deuxième bloc puisque si C = A **⊕** B alors A = B **⊕** C.

Nous avons donc :
61616161616161616161616161616101**⊕** 07c9d338c75ef768daa6136bfceef685  = 66a8b259a63f9609bbc7720a9d8f9784

Ensuite pendant le chiffrement le bloc chiffré #1 (07c9d338c75ef768daa6136bfceef685) va être xoré avec notre deuxième bloc (66a8b259a63f9609bbc7720a9d8f9784) ce qui va donner 61616161616161616161616161616101 en entrée pour le bloc chiffré #2 et donc donner le même tag que notre message original.

[Photo du processus]

Notre message final est donc **6161616161616161616161616161610166a8b259a63f9609bbc7720a9d8f9784**

Cependant tout se processus ne prend en compte que la première partie du tag (bb1e34db8d180f990bbd7b8f10b70269) mais pas la deuxième. Pour la deuxième partie nous devons trouver le tag correspondant en envoyer un troisième message.

Nous savons que la deuxième partie du tag de notre message final correspond à **Enc(10101010101010101010101010101010 **⊕** Enc(66a8b259a63f9609bbc7720a9d8f9784 **⊕** Enc(61616161616161616161616161616101)))**

Heureusement grâce à notre deuxième message nous connaissons le résultat de **Enc(61616161616161616161616161616101)** qui est 362797629fe505aaf93b644810e7d89a

Nous xorons donc **362797629fe505aaf93b644810e7d89a** et **66a8b259a63f9609bbc7720a9d8f9784** 

```
362797629fe505aaf93b644810e7d89a ⊕ 66a8b259a63f9609bbc7720a9d8f9784 = 508f253b39da93a342fc16428d684f1e
```

Nous envoyons donc **508f253b39da93a342fc16428d684f1e** au programme qui va nous donner notre deuxième partie de tag:

```
>>> t
Message (hex):
>>> 508f253b39da93a342fc16428d684f1e
Tag (hex): e997beccbbcfda976efeeb855e2f5ba7fbe31ffd0d9f7cca90c36c67d8cd998b
```

Notre deuxième partie de tag est donc : fbe31ffd0d9f7cca90c36c67d8cd998b.

Nous avons notre message : **6161616161616161616161616161610166a8b259a63f9609bbc7720a9d8f9784**

Nous avons notre tag : **bb1e34db8d180f990bbd7b8f10b70269fbe31ffd0d9f7cca90c36c67d8cd998b**

Vérifions notre tag:

```
>>> v
Message (hex):
>>> 6161616161616161616161616161610166a8b259a63f9609bbc7720a9d8f9784
Tag (hex):
>>> bb1e34db8d180f990bbd7b8f10b70269fbe31ffd0d9f7cca90c36c67d8cd998b
Congrats!! Here is the flag: FCSC{f7c50c0e5ad148a3321d9dd0e72c91420e243b42c9c803814f6d8554163b6260}
```

Et c'est flag.

Cette attaque a évidemment des parades comme ne pas utiliser CBC-MAC mais plutôt HMAC ou RSA.

Le code source et ma solution sont joint.
