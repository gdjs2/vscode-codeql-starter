import cpp

class DerefExpr extends Expr {
	DerefExpr() {
		this instanceof PointerDereferenceExpr or
		this instanceof ArrayExpr
	}
}

from Expr e
where e instanceof DerefExpr
select e, "is an dereference Expression"