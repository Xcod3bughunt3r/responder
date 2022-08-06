#!/usr/bin/env python
"""
@author:       ALIF FUSOBAR
@license:      MIT FUCK LICENSE
@contact:      master@itsecurity.id
"""

import struct

builtin_types = {
    'int': (4, 'i'),
    'long': (4, 'i'),
    'unsigned long': (4, 'I'),
    'unsigned int': (4, 'I'),
    'address': (4, 'I'),
    'char': (1, 'c'),
    'unsigned char': (1, 'B'),
    'unsigned short': (2, 'H'),
    'short': (2, 'h'),
    'long long': (8, 'q'),
    'unsigned long long': (8, 'Q'),
    'pointer': (4, 'I'),
}


def obj_size(types, objname):
    if objname not in types:
        raise Exception('Invalid type %s not in types' % (objname))

    return types[objname][0]


def builtin_size(builtin):
    if builtin not in builtin_types:
        raise Exception('Invalid built-in type %s' % (builtin))

    return builtin_types[builtin][0]


def read_value(addr_space, value_type, vaddr):
    """
    Read the low-level value for a built-in type.
    """

    if value_type not in builtin_types:
        raise Exception('Invalid built-in type %s' % (value_type))

    type_unpack_char = builtin_types[value_type][1]
    type_size = builtin_types[value_type][0]

    buf = addr_space.read(vaddr, type_size)
    if buf is None:
        return None
    (val,) = struct.unpack(type_unpack_char, buf)

    return val


def read_unicode_string(addr_space, types, member_list, vaddr):
    offset = 0
    if len(member_list) > 1:
        (offset, __) = get_obj_offset(types, member_list)

    buf = read_obj(addr_space, types, ['_UNICODE_STRING', 'Buffer'], vaddr + offset)
    length = read_obj(addr_space, types, ['_UNICODE_STRING', 'Length'], vaddr + offset)

    if length == 0x0:
        return ""

    if buf is None or length is None:
        return None

    readBuf = read_string(addr_space, types, ['char'], buf, length)

    if readBuf is None:
        return None

    try:
        readBuf = readBuf.decode('UTF-16').encode('ascii')
    except Exception:  # pylint: disable=broad-except
        return None

    return readBuf


def read_string(addr_space, types, member_list, vaddr, max_length=256):
    offset = 0
    if len(member_list) > 1:
        (offset, __) = get_obj_offset(types, member_list)

    val = addr_space.read(vaddr + offset, max_length)

    return val


def read_null_string(addr_space, types, member_list, vaddr, max_length=256):
    string = read_string(addr_space, types, member_list, vaddr, max_length)

    if string is None:
        return None

    return string.split('\0', 1)[0]


def get_obj_offset(types, member_list):
    """
    Returns the (offset, type) pair for a given list
    """
    member_list.reverse()

    current_type = member_list.pop()

    offset = 0

    while member_list:
        if current_type == 'array':
            current_type = member_dict[current_member][1][2][0]
            if current_type in builtin_types:
                current_type_size = builtin_size(current_type)
            else:
                current_type_size = obj_size(types, current_type)
            index = member_list.pop()
            offset += index * current_type_size
            continue

        elif current_type not in types:
            raise Exception('Invalid type ' + current_type)

        member_dict = types[current_type][1]

        current_member = member_list.pop()
        if current_member not in member_dict:
            raise Exception('Invalid member %s in type %s' % (current_member, current_type))

        offset += member_dict[current_member][0]

        current_type = member_dict[current_member][1][0]

    return (offset, current_type)


def read_obj(addr_space, types, member_list, vaddr):
    """
    Read the low-level value for some complex type's member.
    The type must have members.
    """
    if len(member_list) < 2:
        raise Exception('Invalid type/member ' + str(member_list))

    (offset, current_type) = get_obj_offset(types, member_list)
    return read_value(addr_space, current_type, vaddr + offset)
