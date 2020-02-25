PROG=	checkrestart
MAN=	checkrestart.1
LDADD=	-ljail -lprocstat -lxo
WARNS=	6

.include <bsd.prog.mk>
