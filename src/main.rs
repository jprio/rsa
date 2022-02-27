use mod_exp::mod_exp;
use modinverse::modinverse;
use num::bigint::BigUint;
use num::integer::Integer;
use num::traits::{One, Zero};
use primes::{PrimeSet, Sieve};
use rand::Rng;
use reikna::factor::coprime;
use std::str;

/*L'inverse modulaire de a modulo m existe si seulement si a et m sont premiers entre eux (soit, si le pgcd (a, m) = 1). ...
Si l'inverse modulaire de a modulo m existe, l'opération de division de a modulo m peut être définie comme la multiplication par l'inverse.
Zéro n'a pas d'inverse modulaire.

En mathématiques et plus précisément en arithmétique modulaire,
l'inverse modulaire d'un entier relatif pour la multiplication modulo n est un entier u satisfaisant l'équation :

a*u=1 (mod n)
ex : si a = 5 et n = 11 alors u = 9 car 5*9 = 45 mod 11 = 1
*/
fn mod_inv(a: usize, m: usize) -> Option<usize> {
    for x in 1..m {
        if (a * x) % m == 1 {
            return Some(x);
        }
    }
    return None;
}
#[cfg(test)]
mod tests_mod_inv {
    #[test]
    fn mod_inv() {
        let a = 5;
        let m = 11;
        let inv = super::mod_inv(a, m);
        assert_eq!(inv, Some(9));
    }
}
/*
En mathématiques, plus précisément en arithmétique modulaire, l’exponentiation modulaire est un type d'élévation à la puissance
(exponentiation) réalisée sur des entiers modulo un entier.
Elle est particulièrement utilisée en informatique, spécialement dans le domaine de la cryptologie.
Etant donnés une base b, un exposant e et un entier non nul m, l'exponentiation modulaire consiste à calculer c tel que :
c= b^e(mod m)
o <= c < m

Calculer l'exponentiation modulaire est considéré comme facile, même lorsque les nombres en jeu sont énormes.
Au contraire, calculer le logarithme discret (trouver e à partir de b, c et m) est reconnu comme difficile.
Ce comportement de fonction à sens unique fait de l'exponentiation modulaire une bonne candidate pour être utilisée dans les algorithmes de cryptologie.

*/
fn _mod_exp(b: &BigUint, e: &BigUint, n: &BigUint) -> Result<BigUint, &'static str> {
    if n.is_zero() {
        return Err("modulus is zero");
    }
    if b >= n {
        // base is too large and should be split into blocks
        return Err("base is >= modulus");
    }
    if b.gcd(n) != BigUint::one() {
        return Err("base and modulus are not relatively prime");
    }

    let mut bb = b.clone();
    let mut ee = e.clone();
    let mut result = BigUint::one();
    while !ee.is_zero() {
        if ee.is_odd() {
            result = (result * &bb) % n;
        }
        ee >>= 1;
        bb = (&bb * &bb) % n;
    }
    Ok(result)
}
#[cfg(test)]
mod tests_mod_exp {
    use num::BigUint;

    #[test]
    fn mod_exp() {
        let b = BigUint::from(5u8);
        let e = BigUint::from(11u8);
        let m = BigUint::from(13u8);
        let c = super::_mod_exp(&b, &e, &m);
        // 5^11 mod 13 = 8
        assert_eq!(Some(c.unwrap()), Some(BigUint::from(8u8)));
    }
}
fn get_phi(p: &i128, q: &i128) -> i128 {
    return (p - 1) * (q - 1);
}
fn get_prime() -> i128 {
    let mut pset = Sieve::new();
    let mut rng = rand::thread_rng();
    let (_, n) = pset.find(rng.gen_range(0..1200000));
    //return BigUint::from(941u32);
    return n.into();
}

fn get_sharable_number(p: i128, q: i128) -> i128 {
    //return BigUint::from(2_u64.pow(16) + 1);
    //return BigUint::from(124u32);
    return p * q;
}
/*
The idea! The idea of RSA is based on the fact that it is difficult to factorize a large integer.
 The public key consists of two numbers where one number is multiplication of two large prime numbers. And private key
 is also derived from the same two prime numbers. So if somebody can factorize the large number, the private key is compromised.
 Therefore encryption strength totally lies on the key size and if we double or triple the key size, the strength of encryption increases exponentially.
 RSA keys can be typically 1024 or 2048 bits long, but experts believe that 1024 bit keys could be broken in the near future.
 But till now it seems to be an infeasible task. */
fn main() {
    // Select two prime no's :
    let p = get_prime();
    println!("p : {}", p);

    let q = get_prime();
    println!("q : {}", q);

    /*
    We also need a small exponent say e :
    But e Must be :
    -- An integer.
    -- Not be a factor of n.
    -- 1 < e < Φ(n) [Φ(n) is discussed below],
    select a small odd integer e that is relatively prime to Φ(n), which is Euler's totient function.
    Φ(n) is calculated directly from Euler's formula (its proof is on Wikipedia):
    For n=PQ  where p and q are primes, we get Φ(n) = (P-1)(Q-1).
    */
    let phi_n: i128 = get_phi(&p, &q).try_into().unwrap();

    println!("phi(n) = {}", phi_n);

    let mut e: i128 = 2;
    loop {
        if coprime(phi_n.try_into().unwrap(), e.try_into().unwrap()) {
            break;
        }
        e = e + 1;
    }
    println!("e = {}", e);
    //let e = 2_i128.pow(16) + 1;
    let n = get_sharable_number(p, q);
    println!("n = {}", n);
    //Public Key is made of n and e
    println!("Public Key  : n={}, e={}", n, e);

    //calculate Private Key, d : d = (k*Φ(n) + 1) / e for some integer k

    //let d = mod_inv(e.try_into().unwrap(), phi_n).unwrap();
    let d = modinverse(e, phi_n).unwrap();
    println!("Private Key : n={}, d={}", n, d);
    //let msg = "Rosetta Code";
    let msg = "R";

    //let msg_int = BigUint::from_bytes_be(msg.as_bytes());
    let msg_int = 2;
    println!("Message : {:?}", msg_int);

    let enc = mod_exp(msg_int, e, n);
    let dec = mod_exp(enc, d, n);
    //let msg_dec = String::from_utf8(dec).unwrap();

    println!("msg as txt: {}", msg);
    println!("msg as num: {}", msg_int);

    println!("enc as num: {}", enc);
    println!("{} ^ {} mod {} = {}", p, e, n, enc);
    println!("dec as num: {}", dec);
    println!("{} ^ {} mod {} = {}", enc, d, n, dec);

    //println!("dec as txt: {}", msg_dec);
}
