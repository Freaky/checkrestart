PROG=	checkrestart
MAN=	checkrestart.1
LDADD=	-lprocstat -lxo
WARNS=	6

.include <bsd.prog.mk>
