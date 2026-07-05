export function formatPrice(price){
	let [a,b] = price.toString().split('.')
	let res = '', c = 0

	for(let i = a.length-1; i>=0; i--){
		res = a[i] + res

		if(c++ === 2 && i){
			res = ' ' + res
			c = 0			
		}
	}

	if(b) res += '.' + b

	return res
}

export function parsepath(path){
	const dict = {
		'computers':'Computers',
		'electronics':'Electronics',
		'lenovo': 'Lenovo'
	}
	
	let segments = path.replace(/\/$/,'').split('/')
	segments.shift()

	return {
		
	}
}

export function sitetitle(pagename){
	return pagename + ' — Company'
}

import { sections } from './mock.js'

export let dict = null

export function getSections(){
	function recursion(items){
		for(let item of items){
			item.url = ['/catalog',...item.breadcrumbs].join('/')
			if(item.items) recursion(item.items)
		}
	}

	recursion(sections)

	return sections
}

export async function getDict(){
	if(dict) return dict

	dict = {catalog:'Catalog'}

	function recursion(data){
		for(let item of data){
			dict[item.name_translit] = item.name
			if(item.items) recursion(item.items)
		}
	}

	recursion(sections)
	return dict
}
