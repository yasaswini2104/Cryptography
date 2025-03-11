from sympy import mod_inverse # type: ignore

a = 182841384165841685416854134135
b = 135481653441354138548413384135

try:
    mod_division = (a*mod_inverse(b, a)) % a
    print("Modular Division Result:", mod_division)
except ValueError:
    print("Modular inverse does not exist as b and a are not coprime")
