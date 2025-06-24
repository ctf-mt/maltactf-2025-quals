from random import shuffle

from .paths import root_dir


SWITCH_CASES = """        case opcode(OpcodeIndex::NOP): {
            // NOP: do nothing
            debugln(PC_FMT "NOP", opcode_loc);
            break;
        }
===============================================
        case opcode(OpcodeIndex::LOAD): {
            // LOAD: [ OP, reg, imm8 ] → registers_[reg] = int8_t(imm8)
            const auto [r1, imm8] = consume<2>();
            reg(r1) = static_cast<__int128_t>(imm8);
            debugln(PC_FMT "LOAD R{}, {:#x}", opcode_loc, r1, imm8);
            break;
        }
===============================================
        case opcode(OpcodeIndex::LOAD_32): {
            // LOAD: [ OP, reg, imm32 ] → registers_[reg] = int32_t(imm32)
            const auto [r1] = consume<1>();
            const auto [imm] = consume<1, std::int32_t>();
            reg(r1) = imm;
            debugln(PC_FMT "LOAD_32 R{}, {:#x}", opcode_loc, r1, imm);
            break;
        }
===============================================
        case opcode(OpcodeIndex::LOAD_64): {
            // LOAD: [ OP, reg, imm64 ] → registers_[reg] = int64_t(imm64)
            const auto [r1] = consume<1>();
            const auto [imm] = consume<1, std::int64_t>();
            reg(r1) = imm;
            debugln(PC_FMT "LOAD_64 R{}, {:#x}", opcode_loc, r1, imm);
            break;
        }
===============================================
        case opcode(OpcodeIndex::LOAD_128): {
            // LOAD: [ OP, reg, imm128 ] → registers_[reg] = int128_t(imm64)
            const auto [r1] = consume<1>();
            const auto [imm] = consume<1, __int128_t>();
            reg(r1) = imm;
            debugln(PC_FMT "LOAD_128 R{}, {:#x}", opcode_loc, r1, imm);
            break;
        }
===============================================
        case opcode(OpcodeIndex::ADD): {
            // ADD: [ OP, rd, rs1, rs2 ] → rd = rs1 + rs2
            const auto [rd, rs1, rs2] = consume<3>();
            reg(rd) = reg(rs1).u128 + reg(rs2).u128;
            debugln(PC_FMT "ADD R{}, R{}, R{}", opcode_loc, rd, rs1, rs2);
            break;
        }
===============================================
        case opcode(OpcodeIndex::SUB): {
            // SUB: [ OP, rd, rs1, rs2 ] → rd = rs1 - rs2
            const auto [rd, rs1, rs2] = consume<3>();
            reg(rd) = reg(rs1).u128 - reg(rs2).u128;
            debugln(PC_FMT "SUB R{}, R{}, R{}", opcode_loc, rd, rs1, rs2);
            break;
        }
===============================================
        case opcode(OpcodeIndex::OR): {
            // OR: [ OP, rd, rs1, rs2 ] → rd = rs1 | rs2
            const auto [rd, rs1, rs2] = consume<3>();
            reg(rd) = reg(rs1).u128 | reg(rs2).u128;
            debugln(PC_FMT "OR R{}, R{}, R{}", opcode_loc, rd, rs1, rs2);
            break;
        }
===============================================
        case opcode(OpcodeIndex::NOR): {
            // NOR: [ OP, rd, rs1, rs2 ] → rd = ~(rs1 | rs2)
            const auto [rd, rs1, rs2] = consume<3>();
            reg(rd) = ~(reg(rs1).u128 | reg(rs2).u128);
            debugln(PC_FMT "NOR R{}, R{}, R{}", opcode_loc, rd, rs1, rs2);
            break;
        }
===============================================
        case opcode(OpcodeIndex::ROL): {
            // [OP, rd, rs1, rs2] → rd = rol(rs1, regs[rs2])
            const auto [rd, rs1, rs2] = consume<3>();
            reg(rd) = rol(reg(rs1).u128, reg(rs2).u128 & 0xFF);
            debugln(PC_FMT "ROL R{}, R{}, R{}", opcode_loc, rd, rs1, rs2);
            break;
        }
===============================================
        case opcode(OpcodeIndex::ROR): {
            // [OP, rd, rs1, rs2] → rd = ror(rs1, regs[rs2])
            const auto [rd, rs1, rs2] = consume<3>();
            reg(rd) = ror(reg(rs1).u128, reg(rs2).u128 & 0xFF);
            debugln(PC_FMT "ROR R{}, R{}, R{}", opcode_loc, rd, rs1, rs2);
            break;
        }
===============================================
        case opcode(OpcodeIndex::AND): {
            // AND: [ OP, rd, rs1, rs2 ] → rd = rs1 & rs2
            const auto [rd, rs1, rs2] = consume<3>();
            reg(rd) = reg(rs1).u128 & reg(rs2).u128;
            debugln(PC_FMT "AND R{}, R{}, R{}", opcode_loc, rd, rs1, rs2);
            break;
        }
===============================================
        case opcode(OpcodeIndex::MOD): {
            // MOD: [ OP, rd, rs1, rs2 ] → rd = rs1 % rs2
            const auto [rd, rs1, rs2] = consume<3>();
            if (const auto& rs2_value = reg(rs2); rs2_value.u128 != 0) {
                reg(rd) = reg(rs1).u128 % rs2_value.u128;
            } else {
                std::abort();
            }
            debugln(PC_FMT "MOD R{}, R{}, R{}", opcode_loc, rd, rs1, rs2);
            break;
        }
===============================================
        case opcode(OpcodeIndex::XOR): {
            // XOR: [ OP, rd, rs1, rs2 ] → rd = rs1 ^ rs2
            const auto [rd, rs1, rs2] = consume<3>();
            reg(rd) = reg(rs1).u128 ^ reg(rs2).u128;
            debugln(PC_FMT "XOR R{}, R{}, R{}", opcode_loc, rd, rs1, rs2);
            break;
        }
===============================================
        case opcode(OpcodeIndex::MUL): {
            // MUL: [ OP, rd, rs1, rs2 ] → rd = rs1 * rs2
            const auto [rd, rs1, rs2] = consume<3>();
            reg(rd) = reg(rs1).u128 * reg(rs2).u128;
            debugln(PC_FMT "MUL R{}, R{}, R{}", opcode_loc, rd, rs1, rs2);
            break;
        }
===============================================
        case opcode(OpcodeIndex::PUSH_R): {
            // PUSH_R: [ OP, reg ] → push registers_[reg]
            const auto [r1] = consume<1>();
            push(reg(r1));
            debugln(PC_FMT "PUSH_R R{}", opcode_loc, r1);
            break;
        }
===============================================
        case opcode(OpcodeIndex::POP_R): {
            // POP_R: [ OP, reg ] → pop to registers_[reg]
            const auto [r1] = consume<1>();
            const auto popped_data = pop<sizeof(Register)>();
            std::memcpy(&reg(r1), popped_data.data(), sizeof(Register));
            debugln(PC_FMT "POP_R R{}", opcode_loc, r1);
            break;
        }
===============================================
        case opcode(OpcodeIndex::ADD_STK): {
            // ADD_STK: [ OP ] → pop a, b; push (a + b)
            const auto a = pop_as<Register>();
            const auto b = pop_as<Register>();
            const Register result = a.u128 + b.u128;
            push(result);
            debugln(PC_FMT "ADD_STK (evaluated: {:#x})", opcode_loc, result.u128);
            break;
        }
===============================================
        case opcode(OpcodeIndex::SUB_STK): {
            // SUB_STK: [ OP ] → pop a, b; push (a - b)
            const auto a = pop_as<Register>();
            const auto b = pop_as<Register>();
            const Register result = a.u128 - b.u128;
            push(result);
            debugln(PC_FMT "SUB_STK (evaluated: {:#x})", opcode_loc, result.u128);
            break;
        }
===============================================
        case opcode(OpcodeIndex::OR_STK): {
            // OR_STK: [ OP ] → pop a, b; push (a | b)
            const auto a = pop_as<Register>();
            const auto b = pop_as<Register>();
            const Register result = a.u128 | b.u128;
            push(result);
            debugln(PC_FMT "OR_STK (evaluated: {:#x})", opcode_loc, result.u128);
            break;
        }
===============================================
        case opcode(OpcodeIndex::NOR_STK): {
            // NOR_STK: [ OP ] → pop a, b; push ~(a | b)
            const auto a = pop_as<Register>();
            const auto b = pop_as<Register>();
            const Register result = ~(a.u128 | b.u128);
            push(result);
            debugln(PC_FMT "NOR_STK (evaluated: {:#x})", opcode_loc, result.u128);
            break;
        }
===============================================
        case opcode(OpcodeIndex::ROL_STK): {
            // [OP, rd, rs1, imm8] → pop a,b; push rol(rs1, imm8)
            const auto a = pop_as<Register>();
            const auto b = pop_as<Register>();
            const Register result = rol(a.u128, b.u128);
            push(result);
            debugln(PC_FMT "ROL_STK (evaluated: {:#x})", opcode_loc, result.u128);
            break;
        }
===============================================
        case opcode(OpcodeIndex::ROR_STK): {
            // [OP, rd, rs1, imm8] → pop a,b; push ror(rs1, imm8)
            const auto a = pop_as<Register>();
            const auto b = pop_as<Register>();
            const Register result = ror(a.u128, b.u128);
            push(result);
            debugln(PC_FMT "ROR_STK (evaluated: {:#x})", opcode_loc, result.u128);
            break;
        }
===============================================
        case opcode(OpcodeIndex::AND_STK): {
            // [ OP ] → pop a, b; push (a & b)
            const auto a = pop_as<Register>();
            const auto b = pop_as<Register>();
            const Register result = a.u128 & b.u128;
            push(result);
            debugln(PC_FMT "AND_STK (evaluated: {:#x})", opcode_loc, result.u128);
            break;
        }
===============================================
        case opcode(OpcodeIndex::MOD_STK): {
            // [ OP ] → pop a, b; push (a % b)
            const auto a = pop_as<Register>();
            const auto b = pop_as<Register>();
            const Register result = a.u128 % b.u128;
            push(result);
            debugln(PC_FMT "MOD_STK (evaluated: {:#x})", opcode_loc, result.u128);
            break;
        }
===============================================
        case opcode(OpcodeIndex::XOR_STK): {
            // [ OP ] → pop a, b; push (a ^ b)
            const auto a = pop_as<Register>();
            const auto b = pop_as<Register>();
            const Register result = a.u128 ^ b.u128;
            push(result);
            debugln(PC_FMT "XOR_STK (evaluated: {:#x})", opcode_loc, result.u128);
            break;
        }
===============================================
        case opcode(OpcodeIndex::MUL_STK): {
            // [ OP ] → pop a, b; push (a * b)
            const auto a = pop_as<Register>();
            const auto b = pop_as<Register>();
            const Register result = a.u128 * b.u128;
            push(result);
            debugln(PC_FMT "MUL_STK (evaluated: {:#x})", opcode_loc, result.u128);
            break;
        }
===============================================
        case opcode(OpcodeIndex::JZ): {
            // [OP, reg, offset8] → if (registers_[reg] == 0) pc += offset8
            const auto [r1, offset8_] = consume<2>();
            const auto offset8 = static_cast<std::int8_t>(offset8_);

            const auto reg_value = reg(r1);
            if (reg_value.u128 == 0) {
                pc_ = opcode_loc + offset8;
            }

            debugln(PC_FMT "JZ R{}, {:+d}{}", opcode_loc, r1, offset8, reg_value.u128 == 0 ? " (followed)" : "");
            break;
        }
===============================================
        case opcode(OpcodeIndex::JNZ): {
            // [OP, reg, offset8] → if (registers_[reg] != 0) pc += offset8
            const auto [r1, offset8_] = consume<2>();
            const auto offset8 = static_cast<std::int8_t>(offset8_);

            const auto reg_value = reg(r1);
            if (reg_value.u128 != 0) {
                pc_ = opcode_loc + offset8;
            }

            debugln(PC_FMT "JNZ R{}, {:+d}{}", opcode_loc, r1, offset8, reg_value.u128 != 0 ? " (followed)" : "");
            break;
        }
===============================================
        case opcode(OpcodeIndex::JMP): {
            // [OP, offset8] → pc += offset8
            const auto [offset8_] = consume<1>();
            const auto offset8 = static_cast<std::int8_t>(offset8_);

            pc_ = opcode_loc + offset8;
            debugln(PC_FMT "JMP {:+d}", opcode_loc, offset8);
            break;
        }
===============================================
        case opcode(OpcodeIndex::STOP): {
            // [OP] → stop execution
            debugln(PC_FMT "STOP", opcode_loc);
            running_ = false;
            break;
        }
===============================================
        case opcode(OpcodeIndex::PRINTLN): {
            // [OP] → prints top of the stack
            const auto top = pop_as<Register>();
            std::cout << reinterpret_cast<const char*>(&top.u128) << std::endl;
            debugln(PC_FMT "PRINTLN", opcode_loc, top.u128);
            break;
        }
===============================================
        case opcode(OpcodeIndex::READ): {
            // [OP, reg] → reads at most 16 bytes from stdin into registers_[reg]
            const auto [r1] = consume<1>();
            std::string input;
            input.resize(sizeof(Register));
            std::cin.read(input.data(), sizeof(Register));

            Register value = {};
            std::memcpy(&value.u128, input.data(), std::min(input.size(), sizeof(Register)));
            reg(r1) = value;
            debugln(PC_FMT "READLN R{}", opcode_loc, r1);
            break;
        }""".split('===============================================\n')
VM_CPP_TEMPLATE = (root_dir / 'src' / 'vm' / 'vm.cpp.template').read_text()
VM_CPP_PATH = root_dir / 'src' / 'vm' / 'vm.cpp'


def prepare_vm_cpp() -> None:
    shuffle(SWITCH_CASES)
    content = '// Autogenerated, do not edit!\n'
    content += VM_CPP_TEMPLATE.replace('/* SWITCH CASES */', '\n'.join(SWITCH_CASES))
    VM_CPP_PATH.write_text(content, encoding='utf-8')
