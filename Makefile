SLEIGH_SRC_NAMES := slgh_compile xml slghsymbol grammar pcodeparse slghparse slghscan ruleparse slghpatexpress slghpattern slaformat marshal opcodes translate space pcoderaw address float compression crc32 context semantics globalcontext pcodecompile type database variable cover varnode jumptable emulateutil emulate opbehavior memstate override fspec modelrules cpool architecture prefersplit funcdata_op op heritage rangeutil block funcdata merge funcdata_varnode unionresolve dynamic userop pcodeinject typeop varmap stringmanage flow funcdata_block action transform coreaction constseq subflow double condexe blockaction ruleaction multiprecision options printc ifacedecomp interface capability testfunction callgraph graph paramid printlanguage prettyprint comment loadimage cast sleighbase filemanage

ZLIB_SRC_NAMES := adler32 deflate inffast inflate inftrees trees zutil

SLEIGH_SRCS := $(SLEIGH_SRC_NAMES:%=sleigh/%.c)
ZLIB_SRCS := $(ZLIB_SRC_NAMES:%=zlib/%.c)

SRCS := $(SLEIGH_SRCS) $(ZLIB_SRCS)
OBJS := $(SRCS:%.c=build/%.o)

CXXFLAGS :=
LDFLAGS := -lz

YACC=bison

build/main.elf: $(OBJS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

build/%.o: %.c
	@mkdir -p $(@D)
	$(CXX) -c $(CXXFLAGS) $< -o $@

sleigh/grammar.c: sleigh/grammar.y
	$(YACC) -l -o $@ $<
sleigh/xml.c: sleigh/xml.y
	$(YACC) -l -o $@ $<
sleigh/pcodeparse.c: sleigh/pcodeparse.y
	$(YACC) -l -o $@ $<
sleigh/slghparse.c: sleigh/slghparse.y
	$(YACC) -l -d -o $@ $<
sleigh/slghscan.c: sleigh/slghscan.l
	$(LEX) -L -o$@ $<
sleigh/ruleparse.c: sleigh/ruleparse.y
	$(YACC) -p ruleparse -d -o $@ $<

sleigh/slghparse.hh: sleigh/slghparse.y sleigh/slghparse.c
sleigh/slghscan.c: sleigh/slghparse.hh sleigh/slgh_compile.hh
sleigh/ruleparse.hh: sleigh/ruleparse.y sleigh/ruleparse.c

.phony: clean
clean:
	rm -rf build
