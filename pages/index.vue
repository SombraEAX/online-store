<template lang="pug">
	.global-wrapper.main-page
		site-header
		.landing
			.landing-inner
				h1 Company
				h2 Premium Electronics & Computers
		.info
			.infobox
				.icon.icon-like
				h1 Free Shipping
				p Free standard shipping on all orders over $50. Fast delivery to your doorstep.
			.infobox
				.icon.icon-handshake
				h1 2-Year Warranty
				p Every product comes with a 2-year manufacturer warranty and 30-day money-back guarantee.
			.infobox
				.icon.icon-box
				h1 24/7 Support
				p Our expert support team is available around the clock to help you with any questions.
		.articles
			.article
				img(src="~/assets/images/article-image.jpg")
				.content
					h1 New Apple MacBook Pro with M4 Chip Now Available
					p The latest MacBook Pro features the groundbreaking M4 chip, delivering up to 2.5x faster performance than the previous generation. With up to 24 hours of battery life and a stunning Liquid Retina XDR display, it's the perfect tool for professionals.
					p Pre-order now and get free AppleCare+ for the first year. Available in Space Black and Silver finishes with configurations up to 128 GB of unified memory.
					p Trade in your old MacBook and save up to $650. Limited-time offer while supplies last.			
			.article
				img(src="~/assets/images/article-image.jpg")
				.content
					h1 Summer Sale — Up to 40% Off on Electronics
					p Our biggest sale of the season is here! Save big on wireless headphones, portable speakers, smartphones, and computer components. Brands include Sony, Bose, JBL, Samsung, and many more.
					p Flash deals refresh every 48 hours. Sign in to your account to get early access and exclusive member-only discounts.
					p Free shipping on all orders over $50. Sale ends August 31st. Don't miss out on these incredible deals.
		.catalog
			h1 Catalog
			main-page-category.category(
				v-for="category in catalog.categories"
				:key="category.url"
				:url="category.url"
				:caption="category.name"
				:subcategories="category.items"
				:image="category.image"
			)
		site-footer

</template>

<style scoped lang="scss">
.main-page .catalog h1{
	text-align:center;
	padding:30px
}
.main-page .articles{
	display:flex;
	flex-direction:column;
	align-items:center
}
.main-page .article{
	width:80vw;
	display:flex;
	align-items:center;
	padding-top:20px;
	padding-bottom:20px
}
.main-page .article .content{
	padding-left:20px
}
.main-page .article h1{
	padding-bottom:20px;
	font-size:2vw
}
.main-page .article img{
	width:25vw
}
.main-page .info{
	text-align:center;
	padding-bottom:50px
}
.main-page .infobox{
	width:300px;
	display:inline-block;
	padding:20px;
	text-align:left
}
.main-page .infobox h1{
	font-size:22px;
	text-align:center;
	padding:15px
}
.main-page .infobox p{
	text-align:justify
}
.main-page .infobox .icon{
	width:100%;
	height:60px;
	background-repeat:no-repeat;
	background-position:center;
	background-size:60px		
}
.main-page .icon-like{
	background-image:url("/like.png")
}
.main-page .icon-handshake{
	background-image:url("/handshake.png")
}
.main-page .icon-box{
	background-image:url("/box.png")
}
.main-page .landing{
	background-image:url("/bg.jpg");
	height:50vw;
	background-position:center;
	background-size:cover;
	color:#fff;
	display:flex
}
.main-page .landing-inner{
	margin:auto;
	width:100%;
	background:rgba(0,0,0,0.5);
	text-align:center;
	padding:3vw
}
.main-page .landing-inner>h1{
	font-size:7vw
}
.main-page .landing-inner>h2{
	font-size:3vw
}
.main-page .landing-inner>*{
	font-weight:normal
}
@media (max-width: 1000px) {
	.main-page .infobox{
		width:30vw
	}
	.main-page .infobox .icon{
		background-size:40px;
		height:40px
	}
	.main-page .article{
		width:90vw
	}
	.main-page .article h1{
		font-size:16px
	}
}
@media (max-width: 800px) {
	.main-page .info{
		display:flex;
		flex-direction:column;
		align-items:center
	}
	.main-page .infobox{
		display:block;
		width:400px
	}
	.main-page .article{
		flex-direction:column
	}
	.main-page .article img{
		width:50vw;
		margin:50px
	}
}
@media (min-width: 1000px) {
	.main-page .landing-inner>h1{
		font-size:60px
	}
	.main-page .landing-inner>h2{
		font-size:30px
	}	
}
@media (max-width: 500px) {
	.main-page .infobox{
		width:90%
	}
	.main-page .landing{
		height:300px
	}
	.main-page .landing-inner{
		text-align:left;
		padding-top:25px;
		padding-bottom:25px
	}
	.main-page .landing-inner>h1{
		font-size:25px
	}
	.main-page .landing-inner>h2{
		font-size:14px
	}
}
.main-page .category{
	margin-left:5vw;
	margin-right:5vw;
}
</style>

<script>
	import SiteHeader from '../components/ui/header.vue'
	import SiteFooter from '../components/ui/footer.vue'
	import PageBody from '../components/ui/page.vue'
	import PaginationLinks from '../components/ui/pagination.vue'
	import ItemCard from '../components/ui/item.vue'
	import {sitetitle,getSections} from '../lib.js'
	import MainPageCategory from '../components/ui/main-page-category.vue'

	export default {
		head(){
			return {title:sitetitle('Home page')}	
		},
		components:{
			PageBody,
			PaginationLinks,
			ItemCard,
			SiteHeader,
			SiteFooter,
			MainPageCategory
		},
		async mounted(){
			this.catalog.categories = await getSections()
		},
		name: 'index',
		data(){
			return {
				catalog:{
					categories: []
				}
			}
		}
	}
</script>
