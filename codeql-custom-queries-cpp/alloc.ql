import cpp

class MemoryAllocator extends Expr {
	MemoryAllocator() {
		this instanceof NewExpr or 
		this instanceof NewArrayExpr or (
			this instanceof FunctionCall and
			this.(FunctionCall).getTarget().hasGlobalName("malloc")
		)
	}
}

from Expr e
where e instanceof MemoryAllocator
select e, "is an allocator"