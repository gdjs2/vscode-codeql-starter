import cpp

class MemoryDeallocator extends Expr {
	MemoryDeallocator() {
		this instanceof DeleteExpr or
		this instanceof DeleteArrayExpr or (
			this instanceof FunctionCall and 
			this.(FunctionCall).getTarget().hasGlobalName("free")
		)
		
	}
}

from Expr e
where e instanceof MemoryDeallocator
select e, "is an deallocator"