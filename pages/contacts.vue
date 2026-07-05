<template lang="pug">
	page-body
		h1 Contacts
		p.contacts-paragraph Phone: +1 (555) 123-4567
		p.contacts-paragraph Email: info@company.com
		p.contacts-paragraph LinkedIn: /company/example
		p.contacts-paragraph WhatsApp: +1 (555) 123-4567		
</template>

<script>
	import PageBody from '../components/ui/page.vue'
	import {sitetitle} from '../lib.js'

	export default {
		head(){
			return {title:sitetitle('Contacts')}	
		},
		components:{
			PageBody
		},
		name: 'index'
	}
</script>

<style lang="scss" scoped>
.contacts-paragraph{
	margin-top:10px
}
</style>
