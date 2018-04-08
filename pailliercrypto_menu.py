# -*- coding: utf-8 -*-
"""
Created on Sun May 21 22:34:05 2017

@author: 

Paillier Cryptosystem 
"""
import math
import secrets
import numpy as np
import os.path
import tkinter as tk
###Inicio de funciones relacionadas a módulos

def euclidesextendido(a, b): #función recursiva que nos permitirá obtener el mcd de dos números a y b
                             #como resultado se obtendrán (q,x,y) tales que ax+by = g = mcd(a,b)
    if a == 0:    #si a es igual a cero
        return (b, 0, 1)  # (b= 0x+b)
    else:
        g, y, x = euclidesextendido(b % a, a) #se llama a si misma pero ahora se pasan los marametros (b mod a, a)
        return (g, x - (b // a) * y, y) #en python // es el operador de división pero redondeado al entero inferior más cercano

def modinverso(a, m):  #función que nos permitirá obtener x de ax≡ b mod(n) es decir x≡ a^-1 b mod(n) y si b=1 x≡ a^-1 mod(n)
    g, x, y = euclidesextendido(a, m) #se llama a la función correspondiente al algoritmo de Euclides extendido
    if g != 1: #si mcd(a,m) es diferente de 1
        raise Exception("No existe el inverso") #regresamos excepción indicando el error
    else:
        return (x % m) #en caso contrario regresamos x mod m, que es el valor de x de la expresión ax≡ 1 mod(n)

###Fin de funciones relacionadas a módulos

def checkprime(p):  #función pra verificar que un número p sea primo
	if (p < 2):   #si p es menor a 2, no es primo
		return (False)
	for d in range(2, int(p**0.5)+1):  #ciclo for que iterará desde 2 hasta el valor de sqrt(p), este es el algoritmo de 
	                                    #la división por tentativa
		if (p % d == 0):   #si p modulo d es cero, significa que se encontró un valor que lo divide exactamente, por lo tanto no sería un número primo
			return (False)
	return (True) #en caso de que no se cumpla regresamos True, es decir, p es primo


###Inicio de funciones relacionadas al sistema criptográfico
def KeyGeneration (p, q):
	n = p*q #calculando n, que es el producto de los dos números primos de misma longitud
	
	phin=(p-1)*(q-1) #esto es igual a la función phi de Euler para un número que es producto de 
	                 #dos números primos (en este caso n, producto de p y q)
	
	if (math.gcd(n, phin) != 1): #la primera condición que deben cumplir estos números primos es:
	                             #mcd (pq, (p-1)(q-1))=1, aunque esta propiedad se asegura al tenener números
	                             #primos de la misma longitud, se prueba para incrementar la seguridad del programa en caso
	                             #de que el usuario introduzca números de la misma longitud pero que no sean primos
		raise Exception("Error: los números ingresados no son válidos, recuerda ingresar números primos de la misma longitud")
		return (101)
	       
	g = n+1 #generamos g, esta es una manera alternativa de obtener el número g, que debe cumplir la condición: 
	        # g E Z_n^2; Z_n^2 representa el conjunto de los enteros más pequeños que n^2 y que son primos
	        # relativos a n^2, es decir, requerimos un número g que cumpla la condición mcd(g,n^2) = 1
	
	lambd= phin #gracias a la reducción anterior también se puede reducir el cálculo de lambda, de ser
	            # λ= mcm(p-1, q-1), se reduce a λ = phi(n), siendo este cálculo mucho más eficiente y rápido de procesar
	
	mu = modinverso(lambd, n) #obtenemos mu, que de igual manera, gracias a la reducción g=n+1 se reduce de:
	                         # mu = ((x-1)/n)(g^lambda mod n^2))^-1 mod n     a      mu = lambda^-1 mod n
	
	return (n, g, lambd, mu) #se regresa el valor de la llave pública (n,g) y la llave privada (lambda, mu)


def Encryption (n, g, m): #función responsable del cifrado de m, tomando como argumentos a la llave pública y al "plaintext" m

	flag = True #usamos una bandera para controlar el ciclo while
	r=0 #inicializamos r, que será un valor aleatorio entre 0 y n criptográficamente seguro
	while(flag): #este ciclo while iterará hasta que r sea co-primo de n 
		r = secrets.randbelow(n) #función criptográficamente segura para generar números aleatorios menores a n
		if (math.gcd(r,n)==1): #si r y n son coprimos, flag será falso y saldremos del ciclo, sino seguiremos hasta que sean comprimos
		 	flag=False
		#comienza la parte del cifrado, el algoritmo de cifrado c = g^m * r^n mod n^2 donde c es el "cyphertext" o texto cifrado, pero gracias a la reducción g=1+n
		#se puede reducir a c =  [(1+n*m)*(r^2 mod n^2)]mod n^2, ahorrándonos así una exponenciación que afecta en gran medida el tiempo de ejecución.
	rs = pow(r,n,n**2) #se calcula (r^2 mod n^2) usando la función pow, el primer argumento es el coeficiente, el segundo el exponente y el tercero el módulo a aplicar
	c = ((1+n*m)*rs) % (n**2) #se multipica (1+n*m) con rs, que es igual a (r^2 mod n^2) y después se aplica mod n^2,
		                      #así obteniendo el "cyphertext" c
	return (c) #regresamos el "cyphertext"


def Decryption (lambd, mu, n, c): #función encargada del descifrado del cyphertext, tomando como argumentos a lambd y mu, que son la llave
                                  #privada, a n que proviene de la llave pública y a c, que es el cyphertext a descifrar

    #el algoritmo para descifrar el cyphertext y obtener el plaintext es el siguiente:
    #m = (L(c^λ mod n^2) * mu) mod n donde L(x)= (x-1)/n
	x = pow(c, lambd, n**2)  #calculamos el argumento de L, que es (c^λ mod n^2) 
	ls = (x-1)//n #Evaluamos x (obtenido arriba ) en L: L(c^λ mod n^2)
	m = (ls * mu) % n #obtenemos el plaintext multiplicando el resultado de L(c^λ mod n^2) por mu
	                  #y obteniendo el módulo n
	return (m) #regresamos el plaintext

###Fin de funciones relacionadas al sistema criptográfico


### main
fg=True
while (fg):
	print("\n\n##Sistema criptográfico Paillier##\n")
	print("--¿Qué operación desea realizar?--\n")
	print(">Generar llaves")
	print(">Cifrar")
	print(">Descifrar")
	print(">Salir\n")

	flag=True
	while (flag): #este ciclo será equivalente a un switch de c, dependiendo la selección del usuario se ingresarán a los distintos apartados
		opt = str(input("Opción: ")) #captura la opción que ingreso el usuario
		if (opt=="Generar" or opt=="Generar llaves" or opt=="generar llaves" or opt=="generar"): #generar escrito de multiples maneras
			print("-Por favor, ingresa dos números primos, preferentemente de igual longitud")
			primality=False
			while(not primality):
				p = int(input("Primer primo: ")) #se captura el primer primo
				q = int(input("Segundo primo: ")) #se captura el segundo primo
				if (checkprime(p)):  #si p es primo
					pisprime = True #vovlemos la variable verdadera
				else:
					print("El número p no es primo, intenta de nuevo.")
					pisprime = False #en caso contrario, falsa
				if (checkprime(q)): #si q es primo
					qisprime = True #volvemos la variable verdadera
				else:
					print("El número q no es primo, intenta de nuevo.") #en caso contrario, falsa
					qisprime = False
				if (pisprime and qisprime): #verificamos que las dos condiciones se hayan cumplido
					primality = True #si es así los numeros son primos y salimos del ciclo

			n, g, lam, mu = KeyGeneration(p , q)  #se generan las llaves públicas y privadas de encriptación
			print("La llave pública es: \nn= " + str(n) +"\ng= "+str(g)) #la llave pública se muestra por pantalla
			print("La llave privada es: \nλ= " + str(lam) +"\nμ= "+str(mu))#la llave privada se muestra por pantalla
			flag=False #la bandera se marca como false para salir del ciclo while, esto se hace en todas las conidicones menos en caso de un error

		elif (opt=="cifrar" or opt=="Cifrar"): #cifrar escrito de multiples maneras para entrar aunque el usuario no use mayúsuculas
			print("-Por favor, ingrese su llave pública")#se pide la llave publica, en los criptosistemas, la llave publica es la que permite cifrar
			en = int(input("n = ")) #se captura n
			ge = int(input("g = ")) # se captura g
			print("-Por favor, ingresa el texto a encriptar")
			s = str(input("Texto: "))  #se captura el texto a cifrar

			cs = [0 for x in range(len(s))]  #se genera un array del mismo tamaño que el string a cifrar
			index=0 #se usará esta variable como índice del array
			for let in s: #ciclo for, let tomará el valor de cada caracter del string ingresado
				c = Encryption(en, ge, ord(let)) #se encripta un caracter del string ingresado por el usuario
				#print("El cyphertext es: "+str(c))
				cs[index] = c #introducimos un caracter de la string a cada espacio del array cs
				index +=1 #incrementamos el índice del array

			opi = str(input(print("¿Desea mostrar el texto cifrado?\n >Si/No"))) #preguntamos al usuario si desea mostrar su texto cifrado
			if (opi=="Si" or opi=="si"):
				css = "" #generamos un string vacio
				for c in cs: #para cada elemento c en cs
					css += str(c) #concatenaremos cada c (que son los elementos del array cs) en la cadena css
				print("El texto cifrado es: "+ css) #mostraremos la cadena css

			name = str(input(print("¿Con qué nombre desea guardar el archivo de texto cifrado? \nNombre: "))) #preguntamos con qué nombre guardaremos el archivo
			nparray=np.array(cs) #convertimos el array cs (que contiene cada caracter cifrado) en un array de numpy para usar las funciones de escritura de arrays en archivos
			np.savetxt(name, nparray[None, :], fmt = "%s", delimiter = "!del") #método savetxt() perteneciente a numpy (np), name es el nombre que le pondremos al archivo,
			                                                                   # nparray es el nombre del array numpy que escribiremos en el archivo, [None, :] es para convertir el array a un array2D
			                                                                   # fmt se refiere al tipo de dato que escribiremos, en este caso se usaran strings debido al tamaño de los int que manejamos
			                                                                   # delimiter, hace referencia a el string con el cual separaremos cada elemento del array numpy que introduciremos
			flag=False


		elif (opt=="descifrar" or opt=="Descifrar"): #descifrar escrito de multiples maneras para entrar aunque el usuario no use mayúsuculas
			print("-Por favor, ingrese su llave privada") #pedimos la llave privada
			lami = int(input("λ = ")) #se captura λ
			miu = int(input("μ = "))#se captura μ
			en = int(input("n = "))#se captura n
			ff=True
			while(ff):
				name = str(input("Ingrese el nombre del archivo cifrado. \nNombre: ")) #pedimos el nombre del archivo cifrado
				if (not os.path.exists(name)): #verificamos si el archivo existe, este método regresa True si existo y False en caso contrario
					print("El archivo no existe, intenta otra vez.")
				else: #entonces existe y salimos del ciclo while
					ff=False
			cs = np.genfromtxt(name, dtype = str, delimiter = "!del") #leemos el array cs desde un archivo usando el método genfromtxt, sus argumentos son: 
			                                                          #name: el nombre del archivo a leer, debe de estar en el mismo directorio que el script the python o en su defecto ser una ruta completa
			                                                          #dtype = : como que tipo se leeran los datos del archivo, en este caso elegimos str, dado que nuestos valores cifrados son inclusive más grandes que uint64 (unsigned int64)
			                                                          #delimiter, por que string están separados los datos del array a leer desde el archivo
			ds = "" #declaramos una string vacía, será concatenada con cada caracter descifrado del archivo 
			for let in cs: #para let en cs, es decir, para cada elemento del array cs que contiene los datos encriptados
				m = Decryption(lami, miu, en, int(let)) #descifraremos el elemento actual de la matriz cs, los argumentos de la función son lambda y miu, que forman parte de la llave privada, n que forma parte de la llave
				                                        #pública y let, que es el valor del elemento actual del array cs, int() sirve para convertir el string let a int de python, que tiene una capacidad superior a uint64 ()
				print(ds)
				print(chr(m))
				ds += chr(m) #concatenamos cada caracter descifrado en el string ds

			print("El texto descifrado es: "+ ds) #mostramos el texto cifrado por pantalla
			flag=False

		elif (opt=="Salir" or opt == "salir"): #opción para salir del programa, el valor de flag y fg se harán False para salir del ambos ciclos
			flag=False
			fg=False

		else:
			print("Opción inválida, vuelva a intentarlo.") #se ingresa si hay una opción inválida



