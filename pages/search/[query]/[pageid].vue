<template lang="pug">
	page-body
		article.search-page(v-if="status === 'done'")
			.search-header
				h1 Search results for «{{query}}»
				.subtitle {{text}}
			section(v-if="this.subcategories.length")
				h2 Found categories
				main-page-category(
					v-for="category in subcategories"
					:url="'/catalog/' + category.breadcrumbs.join('/')"
					:caption="category.name"
					:subcategories="[]"
					:image="category.image"
				)
			section(v-if="this.products.length")
				h2 Found products
				item-card(
					v-for="item in products"
					:image="item.image" 
					:name="item.title" 
					:price="item.regularPrice" 
					:link="'/product/'+item.id"
				)
			pagination-links(:total="totalPages",:current="pageid",:url="`/search/${query}/`")
		article.search-page.error(v-if="status === 'no data'")
			.header
				h1 Search results for «{{query}}»
			.outer
				.inner Nothing found			
</template>
<style scoped lang="scss">
.search-page .subtitle{
	padding-top:20px;
	padding-bottom:20px
}
.search-page .search-header{
	padding:10px
}
.search-page .error{
	display:flex;
	flex-direction:column;
	height:100%
}
.search-page .outer{
	flex:1;
	display:flex
}
.search-page .inner{margin:auto}
</style>
<script>
	import PageBody from '../../../components/ui/page.vue'
	import PaginationLinks from '../../../components/ui/pagination.vue'
	import ItemCard from '../../../components/ui/item.vue'
	import {sitetitle} from '../../../lib.js'
import {productsByPath, sections} from '../../../mock.js'
	import MainPageCategory from '../../../components/ui/main-page-category.vue'

	export default {
		components:{
			PageBody,
			PaginationLinks,
			ItemCard,
			MainPageCategory
		},
		head(){
			return {title:sitetitle('Search results')}	
		},
		computed:{
			text(){
				if(this.products.length && this.subcategories.length) return `
					Found ${this.products.length} products and
					${this.subcategories.length} subcategories
				`

				if(this.products.length)
					return `Found ${this.products.length} products`

				return `Found ${this.subcategories.length} subcategories`
			}	
		},
		async mounted(){
			let query = this.$route.params.query.toLowerCase()

			let matchedProducts = []
			for(let key in productsByPath){
				matchedProducts = matchedProducts.concat(
					productsByPath[key].filter(p =>
						p.title.toLowerCase().includes(query)
					)
				)
			}

			let matchedSections = []
			function searchSections(items){
				for(let item of items){
					if(item.name.toLowerCase().includes(query))
						matchedSections.push(item)
					if(item.items) searchSections(item.items)
				}
			}
			searchSections(sections)

			this.products = matchedProducts
			this.subcategories = matchedSections

			this.status =
				this.products.length || this.subcategories.length ?
				'done' : 'no data'
		},
		data(){
			return {
				products: [],
				subcategories:[],
				status:'loading',
				query:this.$route.params.query,
				pageid:this.$route.params.pageid,
				totalPages:1,
				count: 1024,
				items:[
					{name:'Alfa bravo',price:12555,link:'/cuprum',image:'/placeholder.png'}
				]
			}
		}			
	}
</script>
