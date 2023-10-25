# Some features
### If you construct a BN object with “”，it will throw an exception.

```c++
BN bn1("",2);   // throw an exception
BN bn2("", 10); // throw an exception
BN bn3("", 16); // throw an exception

```
### If you construct a BN object that start with an illegal character, it will throw an exception.

```c++
BN bn4("567", 2);   // throw a exception  
BN bn5("abc", 10);  // throw a exception 
BN bn6("xyz", 16);  // throw a exception 

```
### If you construct a BN object with an illegal string, but start with a legal character, it will construct a BN object with the preceding legal string.

```c++
//bn7, bn8, bn9 are all zero.
BN bn7("0567", 2);  // bn7 == 0
BN bn8("0abc", 10); // bn8 == 0
BN bn9("0xyz", 16); // bn9 == 0

```
### If you construct a BN object with a decimal string, it will directly discard the part after the decimal point

```c++
//bn10, bn11, bn12 are all ten.
BN bn10("1010.1", 2);  // bn10 == 10
BN bn11("10.5", 10);   // bn11 == 10
BN bn12("a.5", 16);    // bn12 == 10

```
### For the method: void Div(const BN &d, BN &q, BN &r);

```c++
BN bn13(10);
BN bn14(-10);
BN bn15(3);
BN bn16(-3);
BN bn17, bn18;

// 10 / 3 == 3 ... 1
bn13.Div(bn15, bn17, bn18);
EXPECT_TRUE((bn17 == 3) && (bn18 == 1));  // TRUE!

// -10 / 3 == -3 ... -1
bn14.Div(bn15, bn17, bn18);
EXPECT_TRUE((bn17 == -3) && (bn5 == -1)); // TRUE!

// 10 / -3 == -3 ... 1
bn13.Div(bn16, bn17, bn18);
EXPECT_TRUE((bn17 == -3) && (bn5 == 1)); // TRUE!

// -10 / -3 == 3 ... -1
bn14.Div(bn16, bn17, bn18);
EXPECT_TRUE((bn17 == 3) && (bn18 == -1)); // TRUE!

```

### For shift operations
The symbol "-" is ignored.
```c++
BN bn3("-1011", 2);
BN bn4("-10110000000000",2);
BN bn5("-10",2);
EXPECT_TRUE((bn3 << 10) == bn4);
EXPECT_TRUE((bn3 >> 2) == bn5);
EXPECT_TRUE((bn3 >> 4) == BN::ZERO);
EXPECT_TRUE((bn3 >> 10) == BN::ZERO);
EXPECT_TRUE((bn3 <<= 10) == bn4);
EXPECT_TRUE((bn3 >>= 12) == bn5);
EXPECT_TRUE((bn3 >>= 2) == BN::ZERO);
EXPECT_TRUE((bn3 >>= 10) == BN::ZERO);
```