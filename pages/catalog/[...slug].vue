<template lang="pug">
	page-body
		article.catalog-article(v-if="page === 'category'")
			article.catalog-article(v-if="status === 'done'")
				bread-crumbs
				h1 {{title}}
				.main
					section.catalog-section(v-if="subcategories && subcategories.length")
						h2 Subcategories
						main-page-category(
							v-for="category in subcategories"
							:key="catlink(category)"
							:url="catlink(category)"
							:caption="category.name"
							:subcategories="[]"
							:image="category.image"
						)
					aside.filters(v-if="filterGroups.length")
						h2 Filters
						.filter-group(v-for="group in filterGroups" :key="group.name")
							h3 {{group.name}}
							template(v-if="group.numeric")
								.range
									.range-track
										input.range-input(
											type="range"
											:min="group.min" :max="group.max" :step="group.step"
											:value="rangeMin(group)"
											@input="setRangeMin(group.name, +$event.target.value)"
										)
										input.range-input(
											type="range"
											:min="group.min" :max="group.max" :step="group.step"
											:value="rangeMax(group)"
											@input="setRangeMax(group.name, +$event.target.value)"
										)
									.range-labels
										span {{rangeMin(group)}}{{group.unit}} — {{rangeMax(group)}}{{group.unit}}
							.filter-value(
								v-else
								v-for="value in group.values"
								:key="value"
								:class="{active: isSelected(group.name, value)}"
								@click="toggleFilter(group.name, value)"
							) {{value}}
						button.clear-filters(@click="clearFilters" v-if="hasFilters") Clear filters
					section.catalog-section(v-if="products && products.length")
						h2 Products in category
					item-card(
						v-for="item in products"
						:key="item.id"
						:image="item.image" 
							:name="item.title" 
							:price="item.regularPrice" 
							:link="link(item)"
						)
					section.article.catalog-section(v-if="article")
						h2 {{article.title || "Information"}}
						p {{article.text}}
				pagination-links(:total="totalPages",:current="pageid",:url="`${url}/`")
			article.catalog-article.catalog-error(v-else)
				h1 Catalog
				.catalog-outer
					.catalog-inner No such category
		article.catalog-article(v-if="page === 'main'")
			h1 Catalog
			main-page-category.category(
				v-for="category in catalog.categories"
				:key="category.url"
				:url="category.url"
				:caption="category.name"				
				:subcategories="category.items"
				:image="category.image"
			)
</template>
<style scoped lang="scss">
.catalog-category{
	margin-right:20px !important		
}
.catalog-error{
	display:flex;
	flex-direction:column
}
.catalog-section{
	margin-bottom:20px;
	margin-top:20px
}
.catalog-article{
	min-height:100%
}
.catalog-outer{
	flex:1;
	display:flex
}
.catalog-inner{
	margin:auto
}
.filters{
	margin-bottom:20px;
	padding:15px;
	border:1px solid #ccc;
	border-radius:4px
}
.filters h2{
	margin-bottom:10px
}
.filter-group{
	margin-bottom:12px
}
.filter-group h3{
	font-size:14px;
	margin-bottom:5px;
	color:#555
}
.filter-value{
	display:inline-block;
	padding:3px 10px;
	margin:2px 4px 2px 0;
	border:1px solid #ccc;
	border-radius:3px;
	font-size:13px;
	cursor:pointer;
	color:#333
}
.filter-value:hover{
	border-color:#000099
}
.filter-value.active{
	background:#000099;
	color:#fff;
	border-color:#000099
}
.clear-filters{
	margin-top:5px;
	padding:5px 12px;
	border:1px solid #ccc;
	border-radius:3px;
	background:#fff;
	cursor:pointer;
	font-size:13px
}
.clear-filters:hover{
	background:#eee
}
.range{
	margin:8px 0
}
.range-track{
	position:relative;
	width:100%;
	height:4px;
	background:#ddd;
	border-radius:2px
}
.range-input{
	position:absolute;
	top:0;
	left:0;
	width:100%;
	height:4px;
	-webkit-appearance:none;
	appearance:none;
	background:none;
	pointer-events:none;
	outline:none;
	margin:0;
	padding:0;
	z-index:2
}
.range-input:last-child{
	z-index:3
}
.range-input::-webkit-slider-runnable-track{
	-webkit-appearance:none;
	height:4px;
	background:none
}
.range-input::-moz-range-track{
	appearance:none;
	height:4px;
	background:none
}
.range-input::-webkit-slider-thumb{
	-webkit-appearance:none;
	appearance:none;
	width:16px;
	height:16px;
	border-radius:50%;
	background:#000099;
	cursor:pointer;
	pointer-events:auto;
	border:2px solid #fff;
	box-shadow:0 1px 3px rgba(0,0,0,.3)
}
.range-input::-moz-range-thumb{
	width:16px;
	height:16px;
	border-radius:50%;
	background:#000099;
	cursor:pointer;
	pointer-events:auto;
	border:2px solid #fff;
	box-shadow:0 1px 3px rgba(0,0,0,.3)
}
.range-labels{
	font-size:11px;
	color:#888;
	margin-top:6px;
	text-align:center
}
</style>
<script>
	import PageBody from '../../components/ui/page.vue'
	import BreadCrumbs from '../../components/ui/breadcrumbs.vue'
	import PaginationLinks from '../../components/ui/pagination.vue'
	import ItemCard from '../../components/ui/item.vue'
	import {sitetitle,getDict,getSections} from '../../lib.js'
import {productsByPath, productDetails, sectionsByPath} from '../../mock.js'
	import MainPageCategory from '../../components/ui/main-page-category.vue'
	import CenterBox from '../../components/ui/center.vue'

	function isEmpty(ar){
		if(ar === undefined || ar === null) return true
		if(ar.length === 0) return true
		return false
	}

	function parseNum(val){
		let m = val.match(/^([\d.]+)\s*(GB|TB)/i)
		if(!m) return null
		let n = parseFloat(m[1])
		return m[2].toUpperCase() === 'TB' ? n * 1000 : n
	}

	function detectUnit(values){
		for(let v of values){
			let m = v.match(/^\d[\d.]*\s*(GB|TB)/i)
			if(m) return m[1].toUpperCase()
		}
		return ''
	}

	export default {
		components: {
			PageBody,
			BreadCrumbs,
			PaginationLinks,
			ItemCard,
			MainPageCategory,
			CenterBox
		},
		async mounted(){
			let url = document.location.pathname.replace(/\/$/,'').split('/')

			if(!isNaN(+url[url.length-1])) this.pageid = +url.pop()
			if(this.pageid < 1) this.pageid = 1

			this.url =  url.join('/')

			url.shift()
			url.shift()

			if(url.length){
				this.page = 'category'
				await Promise.all([
					this.loadproducts(url),
					this.loadsubcategories(url),
					this.settitle(url)
				])

				if(
					isEmpty(this.products) &&
					isEmpty(this.subcategories)
				) this.status = 'error'
			}else{
				this.page = 'main'
				this.catalog.categories = await getSections()				
			}
		},
		computed:{
			hasFilters(){
				return Object.keys(this.selectedFilters).length > 0 || Object.keys(this.rangeFilters).length > 0
			}
		},
		methods:{
			link(item){
				return '/product/' + item.id
			},
			catlink(cat){
				return ['/catalog', ...cat.breadcrumbs].join('/')
			},
			async settitle(url){
				let dict = await getDict()
				let title = url[url.length-1]

				this.title = dict[title] || title				
			},
			loadproducts(url){
				const pageSize = 6
				let path = url.join('/')
				let all = productsByPath[path]

				if(all && all.length){
					this.allProducts = all
					this.buildFilters()
					this.applyFilters()
				}
			},
			buildFilters(){
				let groups = {}
				for(let item of this.allProducts){
					let details = productDetails[item.id]
					if(!details || !details.details) continue
					for(let spec of details.details){
						if(!groups[spec.name]) groups[spec.name] = new Set()
						groups[spec.name].add(spec.value)
					}
				}
				let out = Object.entries(groups).map(([name, values]) => {
					let vals = [...values]
					let nums = vals.map(parseNum).filter(v => v !== null)
					let numeric = nums.length === vals.length && vals.length > 1
					let unit = numeric ? detectUnit(vals) : ''
					let step = 1
					let min = nums.length ? Math.min(...nums) : 0
					let max = nums.length ? Math.max(...nums) : 0
					if(max - min > 500) step = 10
					else if(max - min > 100) step = 4
					let r = { name, values: vals, numeric }
					if(numeric){
						r.min = min
						r.max = max
						r.step = step
						r.unit = unit ? ' ' + unit : ''
					}
					return r
				})
				let prices = this.allProducts.map(p => p.regularPrice).filter(p => p != null)
				if(prices.length){
					let min = Math.min(...prices)
					let max = Math.max(...prices)
					let step = max - min > 1000 ? 100 : max - min > 100 ? 10 : 1
					out.unshift({
						name: 'Price',
						numeric: true,
						min, max, step,
						values: [],
						unit: ' $'
					})
				}
				this.filterGroups = out
			},
			toggleFilter(name, value){
				if(!this.selectedFilters[name]) this.selectedFilters[name] = []
				let idx = this.selectedFilters[name].indexOf(value)
				if(idx === -1){
					this.selectedFilters[name].push(value)
				}else{
					this.selectedFilters[name].splice(idx, 1)
					if(!this.selectedFilters[name].length) delete this.selectedFilters[name]
				}
				this.pageid = 1
				this.applyFilters()
			},
			isSelected(name, value){
				return this.selectedFilters[name] && this.selectedFilters[name].includes(value)
			},
			rangeMin(group){
				let r = this.rangeFilters[group.name]
				return r !== undefined && r.min !== undefined ? r.min : group.min
			},
			rangeMax(group){
				let r = this.rangeFilters[group.name]
				return r !== undefined && r.max !== undefined ? r.max : group.max
			},
			setRangeMin(name, val){
				let group = this.filterGroups.find(g => g.name === name)
				if(!group) return
				if(!this.rangeFilters[name]) this.rangeFilters[name] = {}
				this.rangeFilters[name].min = Math.max(group.min, Math.min(val, this.rangeMax(group)))
				this.pageid = 1
				this.applyFilters()
			},
			setRangeMax(name, val){
				let group = this.filterGroups.find(g => g.name === name)
				if(!group) return
				if(!this.rangeFilters[name]) this.rangeFilters[name] = {}
				this.rangeFilters[name].max = Math.min(group.max, Math.max(val, this.rangeMin(group)))
				this.pageid = 1
				this.applyFilters()
			},
			clearFilters(){
				this.selectedFilters = {}
				this.rangeFilters = {}
				this.pageid = 1
				this.applyFilters()
			},
			applyFilters(){
				const pageSize = 6
				let filtered = this.allProducts

				let valueEntries = Object.entries(this.selectedFilters)
				let rangeEntries = Object.entries(this.rangeFilters)

				if(valueEntries.length || rangeEntries.length){
					filtered = this.allProducts.filter(item => {
						let details = productDetails[item.id]
						let needsDetails = valueEntries.length > 0 || rangeEntries.some(([n]) => n !== 'Price')
						if(needsDetails && (!details || !details.details)) return false

						let ok = true

						if(valueEntries.length){
							ok = ok && valueEntries.every(([name, values]) =>
								details.details.some(spec => spec.name === name && values.includes(spec.value))
							)
						}

						if(rangeEntries.length && ok){
							ok = rangeEntries.every(([name, range]) => {
								let min = range.min !== undefined ? range.min : -Infinity
								let max = range.max !== undefined ? range.max : Infinity
								if(name === 'Price'){
									return item.regularPrice >= min && item.regularPrice <= max
								}
								let spec = details.details.find(s => s.name === name)
								if(!spec) return false
								let n = parseNum(spec.value)
								if(n === null) return false
								return n >= min && n <= max
							})
						}

						return ok
					})
				}

				this.filteredCount = filtered.length
				this.totalPages = Math.ceil(filtered.length / pageSize)
				this.products = filtered.slice((this.pageid - 1) * pageSize, this.pageid * pageSize)
			},
			loadsubcategories(url){
				let path = url.join('/')
				let subs = sectionsByPath[path]

				if(subs && subs.length)
					this.subcategories = subs
			}
		},
		head(){
			return {title:sitetitle(this.title)}	
		},
		data(){
			return {
				status: 'done',
				pageid:1,
				totalPages:1,
				article:null,		
				title:'',						
				products:[],
				subcategories:[],
				page:'',
				allProducts:[],
				filterGroups:[],
				selectedFilters:{},
				rangeFilters:{},
				filteredCount:0,
				catalog:{
					categories:[]
				}
			}
		}
	}
</script>
