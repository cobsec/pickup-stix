import random
from config import settings

ruleset_path = settings('deploy')['ruleset_path']

def write_snort_rule(src_IP,dst_IP,src_port,dst_port,proto,msg,sid,detail):
	snort_boilerplate = """alert {{proto}} {{src_IP}} {{src_port}} -> {{dst_IP}} {{dst_port}} (msg:"{{msg}}";{{detail}} sid: {{sid}};)"""
	rule = snort_boilerplate.replace('{{dst_IP}}', dst_IP) \
                                        .replace('{{src_IP}}',src_IP) \
                                        .replace('{{dst_port}}',dst_port) \
                                        .replace('{{src_port}}',src_port) \
                                        .replace('{{proto}}',proto) \
                                        .replace('{{msg}}',msg) \
                                        .replace('{{sid}}',sid) \
                                        .replace('{{detail}}',detail)
	write_to_ruleset(rule, ruleset_path)
	return rule

def generate_snort(obs, obs_type, ref):
	if obs_type == 'Address':
		if len(obs) > 1:
			obs = '[' + ','.join(obs) + ']'
		else:
			#print obs
			obs = str(obs[0])
		dst_IP = obs
                src_IP = '$HOME_NET'
                dst_port = 'any'
                src_port = 'any'
                proto = 'tcp'
                detail = ''
                msg = 'Automated STIX deployment - ' + ref
                sid = '200' + "%0.5d" % random.randint(0,99999)

                rule = write_snort_rule(src_IP,dst_IP,src_port,dst_port,proto,msg,sid,detail)
	elif obs_type == 'DomainName':
		if len(obs) > 1:
			print 'Can only create SNORT rule with 1 domain at a time, taking first.'
		obs = str(obs[0])
		src_IP = '$HOME_NET'
                dst_IP = 'any'
                dst_port = 'any'
                src_port = '53'
                proto = 'udp'
                msg = 'Automated STIX deployment - ' + ref
                sid = '200' + "%0.5d" % random.randint(0,99999)
                # DETAIL needs a content field for the domain request
                content_string = ''
                parsed_domain = obs.split('.')
                if parsed_domain[0] == 'www':
                        parsed_domain.pop(0)
                for item in parsed_domain:
                        content_string = content_string + '|' + str(len(item)).zfill(2) + '|' + item
                detail = 'content:"' + content_string + '|00|";'
                rule = write_snort_rule(src_IP,dst_IP,src_port,dst_port,proto,msg,sid,detail)
	else:
		#print 'Unrecognised Observable Type ' + obs_type
		rule = '{{no_rule}}'

	return rule

def write_to_ruleset(rule, ruleset_path):
	with open(ruleset_path, "a") as myfile:
		myfile.write("\n" + rule)

def snortify_local(local_index):
	#print '<======= Starting SNORT deployment'

	for ind_type in local_index:
		#print ind_type
		for obs in local_index[ind_type]:
			#print obs, local_index[ind_type][obs][0]
			obs_list = [obs]
			rule = generate_snort(obs_list, ind_type, local_index[ind_type][obs][0])
			local_index[ind_type][obs].insert(1,rule)

	return local_index
