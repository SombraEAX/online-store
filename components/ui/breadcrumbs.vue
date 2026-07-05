<template lang="pug">
	bread-crumbs-ui(:breadcrumbs="breadcrumbs")
</template>
<script>
	import {getDict} from '../../lib.js'
	import breadCrumbsUi from './breadcrumbs-ui.vue'
	
	async function parsePath(path){
		let segments = path.replace(/\/$/,'').split('/')
		let breadcrumbs = []
		let last = true
		let dict = await getDict()
	
		segments.shift()

		if(!isNaN(+segments[segments.length-1])) segments.pop()

		for(let i = segments.length-1; i>=0; i--){
			if(!last && segments[0] === 'product') segments[0] = 'catalog'	

			let breadcrumb = {
				url: '/' + segments.join('/') + '/'
			}
			
			let segment = segments.pop()

			breadcrumb.caption = dict[segment] || segment

			breadcrumbs.push(breadcrumb)

			last = false
		}

		return breadcrumbs.reverse()
	}

	export default {
		components:{breadCrumbsUi},
		data(){
			return {
				breadcrumbs: [
				]
			}
		},
		async mounted(){
			this.breadcrumbs = await parsePath(document.location.pathname)
		}
	}
</script>
