<template lang="pug">
	.category
		nuxt-link.image(
			:to="url"
			:style="{backgroundImage:'url(\"'+image+'\")'}"
		)
		.links
			h1
				nuxt-link(:to="url") {{caption}}
			.subcategories(v-if="subcategories")
				.subcategory(v-for="subcategory in subcategories")
					h2
						nuxt-link(:to="subcategory.url") {{subcategory.name}}
					ul.subsubcategories(v-if="subcategory.items")
						li(
							v-for="subsubcategory in subcategory.items"
						)
							.subsubcategory-caption
								nuxt-link(:to="subsubcategory.url") {{subsubcategory.name}}
							.subsubsubcategories(
								v-if="subsubcategory.items"
							)
								.subsubsubcategory(
									v-for="subsubsubcategory in wrapper(subsubcategory.items)"
								)
									span(v-if="!subsubsubcategory.first") !{', '}
									nuxt-link(:to="subsubsubcategory.url") {{subsubsubcategory.name}}
</template>
<style scoped lang="scss">
.category h1{
	font-size:30px
}	
.category h2{
	font-size:25px
}
.category a{
	text-decoration:none 
}
.category .subcategory{
	width:100%;
    break-inside:avoid;
    padding-top:3px;
    padding-bottom:3px;
}
.category .links{
	flex:1;
	margin:auto;
	padding:10px
}
.category .subcategories{
	columns:2;
	-webkit-columns: 2;
	-moz-columns: 2;
}
.category{
	margin:10px;
	display:flex;
	min-height:200px;
}
.category .image{
	background-repeat:no-repeat;
	background-position:center;
	background-size:contain;
	margin:20px;
	width:25vw
}
.category li{
	list-style-type:none
}
.category .subsubcategory-caption{
	font-size:20px
}
.category{
	border:1px solid #ccc
}
.category h1 a, .category  h2 a{
	color:blue !important		
}
.category h1 a:hover, .category  h2 a:hover{
	text-decoration:underline
}
.category .subsubcategory-caption a{
	color:#6666ff !important
}
.category .subsubcategory-caption a:hover{
	text-decoration:underline		
}
.category .subsubsubcategory{
	font-size:14px;
	display:inline
}
.category .subsubsubcategory a{
	color:#888 !important
}
.category .subsubsubcategory a:hover{
	text-decoration:underline
}
@media (max-width: 900px) {
	.category .subcategories{
		columns:1;
		-webkit-columns: 1;
		-moz-columns: 1;
	}
	
}
@media (max-width: 500px) {
	.category{
		flex-direction:column
	}
	.category .links{
		width:100%
	}
	.category .image{
		height:200px;
		width:auto
	}
}
</style>
<script>
	export default{
		props:['url','caption','subcategories','image'],
		methods:{
			wrapper(array){
				if(array instanceof Array && array[0]){
					array[0].first = true
				}
				return array
			}
		}
	}
</script>
