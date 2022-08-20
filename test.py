import numpy as np

#créer un tableau numpy
A = np.array([1, 2, 3])
#les attributs des Arrays Numpy
print(A.shape) #dimensions du tableau (ligne/colonnes)
print(A.size) #nombre d'éléments dans le tableau
print(A.ndim) #affiche la dimension du tableau (1D, 2D, 3D...)

#fonctions de créations particulières :
B = np.pi
B = np.zeros((3, 2)) #créé un tableau de dimensions 3/2 rempli de 0
print(B)
B = np.ones((3, 3)) #créé un tableau de dimensions 3/3 rempli de 1
print(A)
B = np.full((4, 4), 9) #créé un tableau de dimensions 3/3 rempli du chiffre 9
print(B)

#MODULES NUMPY :
np.random.randn(3, 4) #créé un tableau de dimensions 3/4 avec des valeurs suivants la loi Normale
np.random.seed() #permet de fixer une graine et de toujours generer les même nombre grace à cette graine

np.random.rand(3, 4)
np.eye(4) #créé une matrice identité (diagonale = 1)

np.linspace(0, 10, 20) #créé une liste qui répartie la valeur totale 20 dans les cases de 0 à 10
np.arange(0, 10, 1) # créé un tableau de valeur selon un pas donné : ici [1, 2, 3, 4, 5, 6, 7, 8, 9]

range(3, 15, 2) #créé une variable de type range : début, fin, pas
print(list(range(3, 15, 2)))
tab = ['an', 'ab', 'aj', 'ag']
print(list(tab))

a = '192.168.1.20'
print(list(a))
b = list(a)

print(b)
print(str(b))