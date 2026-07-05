<template lang="pug">
	page-body.product
		article(v-if="status==='done'")
			bread-crumbs.bread-crumbs(:breadcrumbs="breadcrumbs")
			h1.mobile {{name}}
			.top-block
				.image(
					:style="{backgroundImage:'url(\"'+image+'\")'}"
				)
				.pad
				.info
					h1.desctop {{name}}
					.code(v-if="code") SKU: {{code}}
					.price ${{price}}
					.description {{description}} 
			.gallery-block(v-if="images && images.length")
				image-gallery(
					:images="images"
					@change="setImage($event)"
				)
			section(v-if="info")
				h2 About
				| {{info}}

			section
				h2 Specifications
				.props
					.prop(v-for="(value,key) in props" :key="key")
						.key {{key}}
						.value(v-html="value")

			section(v-if="files && files.length")
				h2 Documents
				.docs
					nuxt-link.doc(v-for="file in files" :key="file.url" :to="file.url")
						.doc-icon
						.doc-name {{file.name}}
		article.error(v-else)
			.inner Product not found
</template>
<style scoped lang="scss">
.product .error{
	display:flex;
	height:100%		
}
.product .inner{
	margin:auto
}
.product .gallery-block{
	margin-top:30px
}
.product .bread-crumbs{
	margin-bottom:20px
}
.product .docs{
	display:flex
}
.product .doc{
	display:flex;
	flex-direction:column;
	width:100px;
	align-items:center;
	text-decoration:none;
}
.product .doc-icon{
	width:50px;
	height:50px;
	background-image:url('file.png');
	background-size:cover;
	margin-top:10px
}
.product .doc-name{
	padding-top:10px;
	text-decoration:none;
	color:#000
}
.product .doc:hover .doc-name{
	text-decoration:underline;
	color:orange
}
.product .placeholder{
	flex:1
}
.product .mobile{
	display:none
}
.product .prop{
	display:flex;
	padding-top:5px;
	padding-bottom:5px;
	border-bottom:1px solid #ccc
}
.product .key,.product .value{
	flex:1
}
.product .image{
	background-size:contain;
	background-image:none;
	background-position:center;
	background-repeat:no-repeat
}
.product h2{
	padding-top:25px;
	padding-bottom:5px;
	font-weight:normal;
}
.product .top-block{
	display:flex;
}
.product .pad{
	width:4vw
}
.product .image,.product .info{
	flex:1
}
.product .image{
	height:40vw;
	border:1px solid #ccc
}
.product h1 {
	font-size:40px;
	font-weight:normal;
	padding-bottom:20px
}
.product .code{
	color:#888;
	padding-bottom:10px
}
.product .price{
	font-size:22px;
	padding-bottom:40px
}
@media (max-width: 1000px) {
	.product h1 {
		font-size:30px;
	}
}
@media (max-width: 800px) {
	.product .top-block{
		flex-direction:column
	}
	.product .image{
		width:70vw;
		height:70vw;
		min-height:70vw;
		margin:auto;
		margin-bottom:20px
	}
	.product .mobile{
		display:block
	}
	.product .desctop{
		display:none
	}
}
</style>
<script>
	import PageBody from '../../components/ui/page.vue'
	import BreadCrumbs from '../../components/ui/breadcrumbs-ui.vue'
	import ImageGallery from '../../components/ui/gallery.vue'
	import {sitetitle,getDict} from '../../lib.js'
import {productDetails} from '../../mock.js'

	export default {
		components:{
			PageBody,
			BreadCrumbs,
			ImageGallery
		},
		head(){
			return {title:sitetitle(this.name)}	
		},
		async mounted(){
			let id = +this.$route.params.pageid
			let data = productDetails[id]
			let buf = '/catalog/'
			let dict = await getDict()

			if(!data){
				this.status = 'error'
				return
			}

			this.name = data.title
			this.images = data.images?.map(image => image.desktop.url)
			this.price = data.regularPrice
			this.description = data.description

			if(data.details) for(let detail of data.details)
				this.props[detail.name] = detail.value

			this.code = data.code
			this.info = data.info
			this.files = data.files

			this.breadcrumbs = [
				{
					url:'/catalog/',
					caption:'Catalog'
				},
				...data.breadcrumbs.map( breadcrumb => ({
					caption: dict[breadcrumb] || breadcrumb,
					url: buf+=breadcrumb+'/'
				})),
				{
					url: document.location.pathname,
					caption: data.title
				}
			]
			
			if(this.images && this.images.length) this.image = this.images[0]
		},
		methods:{
			setImage(image){
				this.image = image
			}	
		},
		data(){
			return {
				breadcrumbs:[],
				status:'done',
				image: '/no.jpg',
				name: '',
				images: [
				],
				price: null,
				code: null,
				description: null,
				props: {

				},
				files:[
				],
				info: null
			}
		}
	}
</script>
