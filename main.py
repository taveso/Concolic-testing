import parser
import logger

constraint = "RdTmp(32to1(RdTmp(1Uto32(CmpEQ8(32to8(RdTmp(8Uto32(LDle:8(STle(GET(32to8_(PUT(GET(8to32_(PUT(Sub8(GET(32to8_(PUT(RdTmp(8Uto32(LDle:8(STle(GET(32to8_(PUT(Add32(2,RdTmp(8Uto32(LDle:8(STle(LDle:32(INPUT(0))))))))))))))))),GET(32to8_(PUT(RdTmp(8Uto32(LDle:8(Shr32(STle(LDle:32(INPUT(0))),8))))))))))))))))))),4)))))"

def main():
	var_by_size, valgrind_operations = parser.parse_constraint(constraint)
	logger.log(var_by_size, valgrind_operations)

if __name__ == "__main__":
    main()
