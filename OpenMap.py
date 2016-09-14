# -*- coding: utf-8 -*-
"""
Created on Tue Aug 16 13:03:21 2016
@author: cameronn
"""
import os
import xml.etree.cElementTree as ET
import pprint
import re
import collections
import csv
import codecs
import schema
import cerberus



datadir = "data"
datafile = "C:\Users\Cameron\Desktop\duluth2.osm"
DUL_DATA = os.path.join(datadir,datafile)
##statinfo = os.stat('C:\Users\cameronn\Desktop\duluth.osm')



## COUNT VARIOUS TYPES OF TAGS IN DATA
def count_tags(filename):
    counts = collections.defaultdict(int)
    for event, elem in ET.iterparse(filename, events=("start",)):  
        counts[elem.tag] += 1
    return counts

##dul_tags = count_tags(DUL_DATA)
##pprint.pprint(dul_tags)


##GIVEN REGULAR EXPRESSIONS
##Count values of listed items
lower = re.compile(r'^([a-z]|_)*$')
lower_colon = re.compile(r'^([a-z]|_)*:([a-z]|_)*$')
problemchars = re.compile(r'[=\+/&<>;\'"\?%#$@\,\. \t\r\n]')

def key_type(element, keys):
    if element.tag == "tag":
        k_value = element.attrib['k']
        if lower.search(k_value) is not None:
            keys['lower'] += 1
        elif lower_colon.search(k_value) is not None:
            keys['lower_colon'] += 1
        elif problemchars.search(k_value) is not None:
            keys["problemchars"] += 1
        else:
            keys['other'] += 1
    return keys    

##def process_map(filename):
##    keys = {"lower": 0, "lower_colon": 0, "problemchars": 0, "other": 0}
##    for _, element in ET.iterparse(filename):
##        keys = key_type(element, keys)
##    return keys
    
    
##Count Unique Contributors
def user_map(filename):
    users = set()
    for event, elem in ET.iterparse(filename):
        for e in elem:
            if 'uid' in e.attrib:
                users.add(e.attrib['uid'])
    return users
##users = user_map(DUL_DATA)

##Using this print statement as a check
##print "Unique Users", len(users)


def get_postcode(element):
    if (element.attrib['k'] == "tiger:zip_right"):
        postcode = element.attrib['v']
        ##pprint.pprint(postcode)
        return postcode     
    
##Audit Street Names/Types    
street_type_re = re.compile(r'\b\S+\.?$', re.IGNORECASE)
street_types = collections.defaultdict(set)
expected = ["Street", "Avenue", "Boulevard", "Drive", "Court", "Place", "Square", "Lane", "Road", 
            "Trail", "Parkway", "Commons", "Way","Highway", "North", "South", "East", "West",
            "Circle", "Entrance"]
            
mapping = {'HWY' :  'Highway',
           'Rd'  :  'Road',
           'St'  :  'Street',}
            
def audit_street_type(street_types, street_name):
    m = street_type_re.search(street_name)
    if m:
        street_type = m.group()
        if street_type not in expected:
            street_types[street_type].add(street_name)


def is_street_name(elem):
    return (elem.attrib['k'] == "addr:street")
    
def is_phone(elem):
    return (elem.attrib['k'] == "phone")


def audit(osmfile):
    osm_file = open(osmfile, "r")
    street_types = collections.defaultdict(set)
    for event, elem in ET.iterparse(osm_file, events=("start",)):

        if elem.tag == "node" or elem.tag == "way":
            for tag in elem.iter("tag"):
                if is_street_name(tag):
                    audit_street_type(street_types, tag.attrib['v'])
    osm_file.close()
    return street_types


def update_name(name, mapping):

    m = street_type_re.search(name)
    other_street_types = []
    if m:
        street_type = m.group()
        if street_type in mapping.keys():
            name = re.sub(street_type, mapping[street_type], name)
        else:
            other_street_types.append(street_type)

    return name

for street_type, ways in street_types.iteritems():
    for name in ways:
        better_name = update_name(name, mapping, street_type_re)
        print name, "=>", better_name  
        
## Remove all blank spaces, hyphens, and parens in phone numbers, returning numbers as XXXYYYZZZZ
        
def update_phone(phone):
    ##phone=phone.replace("-","").replace(" ","").replace("(","").replace(")","").replace("+","").replace(".","") 
    phone = re.sub(r"[^\d]","",phone)
    return phone

for event, elem in ET.iterparse(DUL_DATA):
    ##if elem.tag == "node" or elem.tag=="way":
    if elem.tag in ("node","way"):
        ##for tag in elem.iter("tag"):
          ##  if tag.attrib['k']=="phone":
        for tag in elem.iterfind("tag[@k='phone']"):
            ##print "{!r}: {!r}".format(tag.attrib['k'],tag.attrib['v'])
            ##print "corrected", update_phone(tag.attrib['v'])        
            print "raw: {!r}\ncorrected: {!r}".format(tag.attrib['v'],update_phone(tag.attrib['v']))


OSM_PATH = "C:\Users\cameronn\Desktop\duluth2.osm"

NODES_PATH = "nodes.csv"
NODE_TAGS_PATH = "nodes_tags.csv"
WAYS_PATH = "ways.csv"
WAY_NODES_PATH = "ways_nodes.csv"
WAY_TAGS_PATH = "ways_tags.csv"

LOWER_COLON = re.compile(r'^([a-z]|_)+:([a-z]|_)+')
PROBLEMCHARS = re.compile(r'[=\+/&<>;\'"\?%#$@\,\. \t\r\n]')

SCHEMA = schema.schema

# Make sure the fields order in the csvs matches the column order in the sql table schema
NODE_FIELDS = ['id', 'lat', 'lon', 'user', 'uid', 'version', 'changeset', 'timestamp']
NODE_TAGS_FIELDS = ['id', 'key', 'value', 'type']
WAY_FIELDS = ['id', 'user', 'uid', 'version', 'changeset', 'timestamp']
WAY_TAGS_FIELDS = ['id', 'key', 'value', 'type']
WAY_NODES_FIELDS = ['id', 'node_id', 'position']

    
def correct_k(k):
    index = k.find(':')
    typ = k[:index]
    k = k[index+1:]    
    return k, typ

def shape_element(element, node_attr_fields=NODE_FIELDS, way_attr_fields=WAY_FIELDS,
                  problem_chars=PROBLEMCHARS, default_tag_type='regular'):
    """Clean and shape node or way XML element to Python dict"""
    
    node_attribs = {}
    way_attribs = {}
    way_nodes = []
    tags = []  # Handle secondary tags the same way for both node and way elements

    # YOUR CODE HERE
    if element.tag == 'node':
        for i in node_attr_fields:
            node_attribs[i] = element.attrib[i]
            
    if element.tag == 'way':
        for i in way_attr_fields:
            way_attribs[i] = element.attrib[i]
        
    for tag in element.iter("tag"):
##Grab postcode from tiger data
        ##postcode = get_postcode(tag)
        ##pprint.pprint(postcode)
# use 'if is_street_name()' function to determine if the attribute matches
        if is_street_name(tag):
            print 'BEFORE'
            print  tag.attrib['v']
            # update tag.attrib['v'] with the return from update_name()
            tag.attrib['v']=update_name(tag.attrib['v'],mapping)
            print 'AFTER'
            print  tag.attrib['v']
            
        if is_phone(tag):
            print 'BEFORE'
            print  tag.attrib['v']
            # update tag.attrib['v'] with the return from update_name()
            tag.attrib['v']=update_phone(tag.attrib['v'])
            print 'AFTER'
            print  tag.attrib['v']
            
        dic = {}
        attributes = tag.attrib
        
        if problem_chars.search(tag.attrib['k']):
            continue
    
        if element.tag=='node':
            dic['id'] = node_attribs['id']
        else:
            dic['id'] = way_attribs['id']
            
        ##if is_street_name(tag):
            ##dic['value'] = update_name(attributes['v'],mapping)
        dic['value'] = attributes['v']

        colon_k = LOWER_COLON.search(tag.attrib['k'])
        if colon_k:
            print colon_k.group(0)
            print tag.attrib['k']
            dic['key'], dic['type'] = correct_k(tag.attrib['k'])
        else:
            dic['key'] = attributes['k']
            dic['type'] = 'regular'
        
        
        #print dic
        tags.append(dic)
    
    if element.tag == 'way':
        position = 0
        for nd in element.iter("nd"):
            way_node_dic = {}
            way_node_dic['id']  =way_attribs['id']
            way_node_dic['node_id'] = nd.attrib['ref']
            way_node_dic['position'] = position
            position = position + 1
            way_nodes.append(way_node_dic)
             
    if element.tag == 'node':
        return {'node': node_attribs, 'node_tags': tags}
    elif element.tag == 'way':
        return {'way': way_attribs, 'way_nodes': way_nodes, 'way_tags': tags}

# ================================================== #
#               Helper Functions                     #
# ================================================== #
def get_element(osm_file, tags=('node', 'way', 'relation')):
    """Yield element if it is the right type of tag"""

    context = ET.iterparse(osm_file, events=('start', 'end'))
    _, root = next(context)
    for event, elem in context:
        if event == 'end' and elem.tag in tags:
            yield elem
            root.clear()


def validate_element(element, validator, schema=SCHEMA):
    """Raise ValidationError if element does not match schema"""
    if validator.validate(element, schema) is not True:
        field, errors = next(validator.errors.iteritems())
        message_string = "\nElement of type '{0}' has the following errors:\n{1}"
        error_strings = (
            "{0}: {1}".format(k, v if isinstance(v, str) else ", ".join(v))
            for k, v in errors.iteritems()
        )
        raise cerberus.ValidationError(
            message_string.format(field, "\n".join(error_strings))
        )


class UnicodeDictWriter(csv.DictWriter, object):
    """Extend csv.DictWriter to handle Unicode input"""

    def writerow(self, row):
        super(UnicodeDictWriter, self).writerow({
            k: (v.encode('utf-8') if isinstance(v, unicode) else v) for k, v in row.iteritems()
        })

    def writerows(self, rows):
        for row in rows:
            self.writerow(row)


# ================================================== #
#               Main Function                        #
# ================================================== #
def process_map(file_in, validate):
    """Iteratively process each XML element and write to csv(s)"""

    with codecs.open(NODES_PATH, 'w') as nodes_file, \
         codecs.open(NODE_TAGS_PATH, 'w') as nodes_tags_file, \
         codecs.open(WAYS_PATH, 'w') as ways_file, \
         codecs.open(WAY_NODES_PATH, 'w') as way_nodes_file, \
         codecs.open(WAY_TAGS_PATH, 'w') as way_tags_file:

        nodes_writer = UnicodeDictWriter(nodes_file, NODE_FIELDS)
        node_tags_writer = UnicodeDictWriter(nodes_tags_file, NODE_TAGS_FIELDS)
        ways_writer = UnicodeDictWriter(ways_file, WAY_FIELDS)
        way_nodes_writer = UnicodeDictWriter(way_nodes_file, WAY_NODES_FIELDS)
        way_tags_writer = UnicodeDictWriter(way_tags_file, WAY_TAGS_FIELDS)

        nodes_writer.writeheader()
        node_tags_writer.writeheader()
        ways_writer.writeheader()
        way_nodes_writer.writeheader()
        way_tags_writer.writeheader()

        validator = cerberus.Validator()

        for element in get_element(file_in, tags=('node', 'way')):
            el = shape_element(element)
            if el:
                if validate is True:
                    validate_element(el, validator)

                if element.tag == 'node':
                    nodes_writer.writerow(el['node'])
                    node_tags_writer.writerows(el['node_tags'])
                elif element.tag == 'way':
                    ways_writer.writerow(el['way'])
                    way_nodes_writer.writerows(el['way_nodes'])
                    way_tags_writer.writerows(el['way_tags'])


##print process_map(OSM_PATH, validate=True)

  
def test():
    st_types = audit(DUL_DATA)
    pprint.pprint(dict(st_types))

    

    for st_type, ways in st_types.iteritems():
        for name in ways:
            better_name = update_name(name, mapping)
            print name, "=>", better_name

##if __name__ == '__main__':
test()


